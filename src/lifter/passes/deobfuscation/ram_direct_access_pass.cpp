// ram_direct_access_pass.cpp
// LLVM 16+ function-level pass (new pass manager).
// Rewrites loads/stores through GEPs into @RAM into direct loads/stores
// using inttoptr(ptrtoint(@RAM) + index).

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

struct RAMDirectAccessPass : public PassInfoMixin<RAMDirectAccessPass> {
  // Name of the global to match:
  static constexpr const char *RAMName = "RAM";

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    Module *M = F.getParent();
    LLVMContext &Ctx = M->getContext();
    const DataLayout &DL = M->getDataLayout();

    // Pointer- and integer-types we will use.
    Type *PtrTy = PointerType::get(Ctx, 0);    // opaque pointer
    Type *I64Ty = Type::getInt64Ty(Ctx);

    GlobalVariable *RAM = M->getGlobalVariable(RAMName);
    if (!RAM) {
      // No RAM global in this module — nothing to do.
      return PreservedAnalyses::all();
    }

    SmallVector<Instruction *, 32> ToErase;

    // Helper: given a Value* that should be an index, return an i64-typed Value*
    // representing that index (with zext/trunc as necessary).
    auto ensureI64 = [&](IRBuilder<> &B, Value *V) -> Value * {
      if (V->getType()->isIntegerTy(64))
        return V;
      if (auto *IT = dyn_cast<IntegerType>(V->getType())) {
        unsigned w = IT->getBitWidth();
        if (w < 64)
          return B.CreateZExt(V, I64Ty, "idx.zext");
        else if (w > 64)
          return B.CreateTrunc(V, I64Ty, "idx.trunc");
      }
      // If index isn't integer, try to bitcast via integer of same size (rare).
      // Fallback: attempt to convert pointer to integer (pointer index -> int)
      if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, I64Ty, "idx.ptrtoint");
      // Otherwise, as a last resort, try treating it as i64(0)
      return ConstantInt::get(I64Ty, 0);
    };

    // Iterate and transform.
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        // ---- Handle loads ----
        if (auto *LI = dyn_cast<LoadInst>(&I)) {
          Value *PtrOp = LI->getPointerOperand();

          // Strip pointer casts to find an underlying GEP.
          Value *Stripped = PtrOp->stripPointerCasts();
          auto *GEP = dyn_cast<GetElementPtrInst>(Stripped);
          if (!GEP)
            continue;

          // GEP's base should be the RAM global (maybe via a bitcast), check that.
          Value *GEPBase = GEP->getPointerOperand()->stripPointerCasts();
          if (GEPBase != RAM)
            continue;

          // Typical form: getelementptr [0 x i8], ptr @RAM, i64 0, i64 idx
          // We'll try to find the last index (after the first zero) as the byte offset.
          SmallVector<Value *, 4> IdxVals;
          for (auto IdxIt = GEP->idx_begin(); IdxIt != GEP->idx_end(); ++IdxIt)
            IdxVals.push_back(IdxIt->get());

          if (IdxVals.empty())
            continue;

          // Strategy: compute base_int = ptrtoint(@RAM)
          IRBuilder<> B(LI);
          Value *RAMPtr = GEP->getPointerOperand(); // original pointer to @RAM (may be bitcasted)
          Value *RAMPtrStripped = RAMPtr->stripPointerCasts(); // should be @RAM
          // ptrtoint(RAMPtr) to i64
          Value *BaseInt = B.CreatePtrToInt(RAMPtr, I64Ty, "ram.base.ptrtoint");

          // Combine indices: for simple [0, idx] the effective byte offset is the last index
          // when element type is i8. For generality we will compute the scaled offset
          // by using the GEP itself converted to an integer:
          //   gepPtr = GEP (ptr)
          //   gepAddrInt = ptrtoint(gepPtr)
          // and then subtract baseInt to obtain idxInt:
          Value *GEPPtr = GEP; // pointer produced by GEP
          Value *GEPAddrInt = B.CreatePtrToInt(GEPPtr, I64Ty, "gep.addr.ptrtoint");
          Value *IdxInt = B.CreateSub(GEPAddrInt, BaseInt, "idx.bytes");

          // Now compute addr = BaseInt + IdxInt  (this essentially equals GEPAddrInt,
          // but we keep it explicit for readability). We'll just use GEPAddrInt as finalAddr:
          Value *FinalAddr = GEPAddrInt;

          // Convert final address to the pointer type the load expects (opaque ptr -> typed pointer not available).
          // The load expects a result-typed pointer; we can use the original PtrOp type (which may be a bitcast).
          Type *ExpectedPtrTy = PtrOp->getType(); // should be a pointer type
          if (!ExpectedPtrTy->isPointerTy())
            continue; // unexpected

          // Create inttoptr(finalAddr to ExpectedPtrTy)
          Value *NewPtr = B.CreateIntToPtr(FinalAddr, ExpectedPtrTy, "ram.inttoptr");

          // If original PtrOp had pointer casts, the LI might have been loading from a bitcasted pointer.
          // To be safe, preserve alignment, volatility, atomic ordering and metadata.
          LoadInst *NewLoad = B.CreateLoad(LI->getType(), NewPtr, LI->getName() + ".ram.direct");
          // copy alignment
          NewLoad->setAlignment(LI->getAlign());
          // copy volatile/atomic properties
          if (LI->isVolatile())
            NewLoad->setVolatile(true);
          if (LI->isAtomic())
            NewLoad->setAtomic(LI->getOrdering());
          if (LI->getSyncScopeID() != SyncScope::SingleThread)
            NewLoad->setSyncScopeID(LI->getSyncScopeID());
          // copy metadata
          NewLoad->copyMetadata(*LI);

          // Replace uses and schedule erase of old instructions
          LI->replaceAllUsesWith(NewLoad);
          ToErase.push_back(LI);

          // If the GEP has no other uses (other than PtrOp or LI), erase it too later.
          if (GEP->use_empty())
            ToErase.push_back(GEP);

        } // end load handling

        // ---- Handle stores ----
        else if (auto *SI = dyn_cast<StoreInst>(&I)) {
          Value *PtrOp = SI->getPointerOperand();
          Value *ValueOp = SI->getValueOperand();

          Value *Stripped = PtrOp->stripPointerCasts();
          auto *GEP = dyn_cast<GetElementPtrInst>(Stripped);
          if (!GEP)
            continue;

          Value *GEPBase = GEP->getPointerOperand()->stripPointerCasts();
          if (GEPBase != RAM)
            continue;

          // Build new pointer like for loads:
          IRBuilder<> B(SI);
          Value *RAMPtr = GEP->getPointerOperand();
          Value *GEPAddrInt = B.CreatePtrToInt(GEP, I64Ty, "gep.addr.ptrtoint");
          // Final address
          Value *FinalAddr = GEPAddrInt;

          Type *ExpectedPtrTy = PtrOp->getType();
          if (!ExpectedPtrTy->isPointerTy())
            continue;

          Value *NewPtr = B.CreateIntToPtr(FinalAddr, ExpectedPtrTy, "ram.inttoptr");

          // If value is floating point and store's pointer expects integer type, bitcast as needed.
          Value *ValToStore = ValueOp;
          if (ValToStore->getType()->isFloatingPointTy()) {
            // For stores, the pointer type indicates the stored type. If mismatch, attempt bitcast via integer.
            // We'll only bitcast value to integer of same width if necessary.
            unsigned bits = DL.getTypeSizeInBits(ValToStore->getType());
            Type *IntTy = IntegerType::get(Ctx, bits);
            ValToStore = B.CreateBitCast(ValToStore, IntTy, "store.fp.toint");
          }

          StoreInst *NewStore = B.CreateStore(ValToStore, NewPtr);
          NewStore->setAlignment(SI->getAlign());
          if (SI->isVolatile())
            NewStore->setVolatile(true);
          if (SI->isAtomic())
            NewStore->setAtomic(SI->getOrdering());
          if (SI->getSyncScopeID() != SyncScope::SingleThread)
            NewStore->setSyncScopeID(SI->getSyncScopeID());
          NewStore->copyMetadata(*SI);

          ToErase.push_back(SI);
          if (GEP->use_empty())
            ToErase.push_back(GEP);
        }
      }
    }

    // Erase old instructions (do outside iteration).
    for (Instruction *I : ToErase) {
      // Check still in parent (may have been erased earlier)
      if (I->hasNUsesOrMore(0)) {
        // If it wasn't already removed
        if (I->getParent())
          I->eraseFromParent();
      }
    }

    return PreservedAnalyses::none();
  } // run
};

} // namespace

// Pass plugin boilerplate
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "ram-direct-access-pass", "v0.1",
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, FunctionPassManager &FPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              if (Name == "ram-direct-access") {
                FPM.addPass(RAMDirectAccessPass());
                return true;
              }
              return false;
            });
      }};
}
