// memory_intrinsic_lowering_pass.cpp
// LLVM-16+ FunctionPass using opaque pointers.
// Replaces all loads/stores with calls to:
//   __remill_read_memory_{8,16,32,64}(ptr, i64)
//   __remill_write_memory_{8,16,32,64}(ptr, i64, iN)

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"

#include "memory_intrinsic_lowering_pass.hpp"

using namespace llvm;

GlobalVariable *findRAMGlobal(Module &M)
{
  // Preferred: a global named "RAM".
  if (GlobalVariable *G = M.getGlobalVariable("RAM"))
    return G;
  // Fallback: any global used as base of GEPs with element [0 x i8].
  for (GlobalVariable &G : M.globals())
  {
    for (User *U : G.users())
    {
      if (auto *GEP = dyn_cast<GetElementPtrInst>(U))
      {
        if (auto *AT = dyn_cast<ArrayType>(GEP->getSourceElementType()))
        {
          if (AT->getElementType()->isIntegerTy(8))
            return &G;
        }
      }
    }
  }
  return nullptr;
}

PreservedAnalyses MemoryIntrinsicLoweringPass::run(Function &F, FunctionAnalysisManager &)
{
  Module *M = F.getParent();
  LLVMContext &Ctx = M->getContext();
  const DataLayout &DL = M->getDataLayout();

  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  GlobalVariable *RAM = findRAMGlobal(*M);
  if (!RAM)
  {
    errs() << "[memory-intrinsic-lowering] No RAM global found in module " << M->getName() << "\n";
    return PreservedAnalyses::all();
  }

  auto getReadFunc = [&](unsigned bits) -> FunctionCallee
  {
    Type *RetTy = IntegerType::get(Ctx, bits);
    FunctionType *FT =
        FunctionType::get(RetTy, {I64Ty}, false);
    return M->getOrInsertFunction(
        ("__lifted_read_memory_" + std::to_string(bits)).c_str(), FT);
  };

  auto getWriteFunc = [&](unsigned bits) -> FunctionCallee
  {
    Type *ValTy = IntegerType::get(Ctx, bits);
    FunctionType *FT =
        FunctionType::get(VoidTy, {I64Ty, ValTy}, false);
    return M->getOrInsertFunction(
        ("__lifted_write_memory_" + std::to_string(bits)).c_str(), FT);
  };

  auto isRAMAccessGEP = [&](Value *P) -> GetElementPtrInst *
  {
    if (auto *GEP = dyn_cast<GetElementPtrInst>(P))
    {
      return GEP->getPointerOperand()->stripPointerCasts() == RAM ? GEP : nullptr;
    }
    return nullptr;
  };

  SmallVector<Instruction *> ToErase;
  SmallPtrSet<Instruction *, 8> ToEraseGEPSet;

  for (BasicBlock &BB : F)
  {
    for (Instruction &I : BB)
    {
      // ---- LOAD ----
      if (auto *LI = dyn_cast<LoadInst>(&I))
      {
        Type *Ty = LI->getType();
        if (!Ty->isIntegerTy())
          continue;

        if (isa<Argument>(LI->getPointerOperand()))
          continue;

        unsigned Bits = Ty->getScalarSizeInBits();
        if (Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64)
          continue;

        if (auto GEP = isRAMAccessGEP(LI->getPointerOperand()))
        {
          Value *Addr = GEP->getOperand(GEP->getNumOperands() - 1);

          IRBuilder<> B(LI);

          FunctionCallee Callee = getReadFunc(Bits);
          Value *Call = B.CreateCall(Callee, {Addr}, "remill.load");

          if (Call->getType() != Ty)
            Call = B.CreateZExtOrTrunc(Call, Ty);
          LI->replaceAllUsesWith(Call);

          ToErase.push_back(LI);
          ToEraseGEPSet.insert(GEP);
        }
      }

      // ---- STORE ----
      else if (auto *SI = dyn_cast<StoreInst>(&I))
      {
        Value *Val = SI->getValueOperand();
        Type *Ty = Val->getType();
        if (!Ty->isIntegerTy())
          continue;

        if (isa<Argument>(SI->getPointerOperand()))
          continue;

        unsigned Bits = Ty->getScalarSizeInBits();
        if (Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64)
          continue;

        if (auto GEP = isRAMAccessGEP(SI->getPointerOperand()))
        {
          Value *Addr = GEP->getOperand(GEP->getNumOperands() - 1);

          IRBuilder<> B(SI);
          FunctionCallee Callee = getWriteFunc(Bits);
          B.CreateCall(Callee, {Addr, Val});
          ToErase.push_back(SI);
          ToEraseGEPSet.insert(GEP);
        }
      }
    }
  }

  for (Instruction *I : ToErase)
    I->eraseFromParent();
  for (Instruction *I : ToEraseGEPSet)
    if (I->use_empty())
      I->eraseFromParent();

  return PreservedAnalyses::none();
}

// ---- Pass registration ----
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
  return {LLVM_PLUGIN_API_VERSION, "lower-memory-intrinsics", "v1.0",
          [](PassBuilder &PB)
          {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>)
                {
                  if (Name == "lower-memory-intrinsics")
                  {
                    FPM.addPass(MemoryIntrinsicLoweringPass());
                    return true;
                  }
                  return false;
                });
          }};
}
