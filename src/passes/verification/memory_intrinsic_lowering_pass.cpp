// memory_intrinsic_lowering_pass.cpp
// LLVM-16+ FunctionPass using opaque pointers.
// Replaces all loads/stores with calls to:
//   __remill_read_memory_{8,16,32,64}(ptr, i64)
//   __remill_write_memory_{8,16,32,64}(ptr, i64, iN)

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

  Type *PtrTy = PointerType::get(Ctx, 0);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  GlobalVariable *RAM = findRAMGlobal(*M);
  if (!RAM)
  {
    errs() << "[memory-intrinsic-lowering] No RAM global found in module " << M->getName() << "\n";
    return PreservedAnalyses::all();
  }

  auto findMemoryValue = [&](Function &Fn) -> Value *
  {
    if (Fn.arg_empty())
      return nullptr;
    return Fn.arg_begin() + 1;
  };

  Value *MemoryVal = findMemoryValue(F);
  if (!MemoryVal)
  {
    errs() << "[memory-intrinsic-lowering] No Memory* found in function " << F.getName() << "\n";
    return PreservedAnalyses::all();
  }

  auto getReadFunc = [&](unsigned bits) -> FunctionCallee
  {
    Type *RetTy = IntegerType::get(Ctx, bits);
    FunctionType *FT =
        FunctionType::get(RetTy, {PtrTy, I64Ty}, false);
    return M->getOrInsertFunction(
        ("__remill_read_memory_" + std::to_string(bits)).c_str(), FT);
  };

  auto getWriteFunc = [&](unsigned bits) -> FunctionCallee
  {
    Type *ValTy = IntegerType::get(Ctx, bits);
    FunctionType *FT =
        FunctionType::get(PtrTy, {PtrTy, I64Ty, ValTy}, false);
    return M->getOrInsertFunction(
        ("__remill_write_memory_" + std::to_string(bits)).c_str(), FT);
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

        IRBuilder<> B(LI);

        Value *Addr = nullptr;
        if (auto GEP = isRAMAccessGEP(LI->getPointerOperand()))
        {
          Addr = GEP->getOperand(GEP->getNumOperands() - 1);
        }
        else
        {
          Addr = B.CreatePtrToInt(LI->getPointerOperand(), I64Ty);
        }

        FunctionCallee Callee = getReadFunc(Bits);
        Value *Call = B.CreateCall(Callee, {MemoryVal, Addr}, "remill.load");

        if (Call->getType() != Ty)
          Call = B.CreateZExtOrTrunc(Call, Ty);
        LI->replaceAllUsesWith(Call);

        ToErase.push_back(LI);
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

        IRBuilder<> B(SI);

        Value *Addr = nullptr;
        if (auto GEP = isRAMAccessGEP(SI->getPointerOperand()))
        {
          Addr = GEP->getOperand(GEP->getNumOperands() - 1);
        }
        else
        {
          Addr = B.CreatePtrToInt(SI->getPointerOperand(), I64Ty);
        }

        FunctionCallee Callee = getWriteFunc(Bits);
        B.CreateCall(Callee, {MemoryVal, Addr, Val});
        ToErase.push_back(SI);
      }
    }
  }

  for (Instruction *I : ToErase)
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
