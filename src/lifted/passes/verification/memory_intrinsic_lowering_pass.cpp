// memory_intrinsic_lowering_pass.cpp
// LLVM-16+ FunctionPass using opaque pointers.
// Replaces RAM-backed scalar loads/stores and bulk memory intrinsics with
// verifier helper calls.

#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"

#include "../pass_utils.hpp"
#include "memory_intrinsic_lowering_pass.hpp"

#include <optional>

using namespace llvm;

namespace {

Value *castSignedToI64(IRBuilder<> &B, Value *V, Type *I64Ty)
{
  if (V->getType() == I64Ty)
    return V;
  return B.CreateIntCast(V, I64Ty, true);
}

Value *castUnsignedToI64(IRBuilder<> &B, Value *V, Type *I64Ty)
{
  if (V->getType() == I64Ty)
    return V;
  return B.CreateIntCast(V, I64Ty, false);
}

std::optional<Value *> tryBuildRAMAddress(Value *Ptr, GlobalVariable *RAM,
                                          const DataLayout &DL,
                                          IRBuilder<> &B, Type *I64Ty)
{
  Value *Stripped = Ptr->stripPointerCasts();
  if (Stripped == RAM)
    return ConstantInt::get(I64Ty, 0);

  auto *GEP = dyn_cast<GEPOperator>(Stripped);
  if (!GEP)
    return std::nullopt;

  auto BaseAddr = tryBuildRAMAddress(GEP->getPointerOperand(), RAM, DL, B, I64Ty);
  if (!BaseAddr)
    return std::nullopt;

  unsigned PtrBits = DL.getIndexTypeSizeInBits(GEP->getType());
  MapVector<Value *, APInt> VariableOffsets;
  APInt ConstantOffset(PtrBits, 0, true);
  if (!GEP->collectOffset(DL, PtrBits, VariableOffsets, ConstantOffset))
    return std::nullopt;

  Value *Addr = *BaseAddr;
  if (ConstantOffset != 0)
  {
    Addr = B.CreateAdd(
        Addr,
        ConstantInt::get(I64Ty, ConstantOffset.sextOrTrunc(64)),
        "ram.addr");
  }

  for (auto &[Term, Scale] : VariableOffsets)
  {
    Value *Scaled = castSignedToI64(B, Term, I64Ty);
    if (Scale != 1)
    {
      Scaled = B.CreateMul(
          Scaled,
          ConstantInt::get(I64Ty, Scale.sextOrTrunc(64)),
          "ram.addr.scale");
    }
    Addr = B.CreateAdd(Addr, Scaled, "ram.addr");
  }

  return Addr;
}

void collectCleanupRoot(Value *V, SmallPtrSetImpl<Instruction *> &CleanupRoots)
{
  if (auto *I = dyn_cast<Instruction>(V))
    CleanupRoots.insert(I);
}

} // namespace

PreservedAnalyses MemoryIntrinsicLoweringPass::run(Function &F, FunctionAnalysisManager &)
{
  Module *M = F.getParent();
  LLVMContext &Ctx = M->getContext();
  const DataLayout &DL = M->getDataLayout();

  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  GlobalVariable *RAM = lifted::passes::getRAM(*M);
  if (!RAM)
  {
    errs() << "[memory-intrinsic-lowering] No RAM global found in module " << M->getName() << "\n";
    return PreservedAnalyses::all();
  }

  auto getReadFunc = [&](unsigned Bits) -> FunctionCallee {
    Type *RetTy = IntegerType::get(Ctx, Bits);
    FunctionType *FT = FunctionType::get(RetTy, {I64Ty}, false);
    return M->getOrInsertFunction(
        ("__lifted_read_memory_" + std::to_string(Bits)).c_str(), FT);
  };

  auto getWriteFunc = [&](unsigned Bits) -> FunctionCallee {
    Type *ValTy = IntegerType::get(Ctx, Bits);
    FunctionType *FT = FunctionType::get(VoidTy, {I64Ty, ValTy}, false);
    return M->getOrInsertFunction(
        ("__lifted_write_memory_" + std::to_string(Bits)).c_str(), FT);
  };

  FunctionCallee MemSetFunc = M->getOrInsertFunction(
      "__lifted_memset_memory",
      FunctionType::get(VoidTy, {I64Ty, I8Ty, I64Ty}, false));
  FunctionCallee MemCpyFunc = M->getOrInsertFunction(
      "__lifted_memcpy_memory",
      FunctionType::get(VoidTy, {I64Ty, I64Ty, I64Ty}, false));
  FunctionCallee MemMoveFunc = M->getOrInsertFunction(
      "__lifted_memmove_memory",
      FunctionType::get(VoidTy, {I64Ty, I64Ty, I64Ty}, false));

  SmallVector<Instruction *> ToErase;
  SmallPtrSet<Instruction *, 16> CleanupRoots;
  bool Changed = false;

  for (BasicBlock &BB : F)
  {
    for (Instruction &I : BB)
    {
      if (auto *LI = dyn_cast<LoadInst>(&I))
      {
        Type *Ty = LI->getType();
        if (!Ty->isIntegerTy())
          continue;

        unsigned Bits = Ty->getScalarSizeInBits();
        if (Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64)
          continue;

        IRBuilder<> B(LI);
        auto Addr = tryBuildRAMAddress(LI->getPointerOperand(), RAM, DL, B, I64Ty);
        if (!Addr)
          continue;

        Value *Call = B.CreateCall(getReadFunc(Bits), {*Addr}, "remill.load");
        if (Call->getType() != Ty)
          Call = B.CreateZExtOrTrunc(Call, Ty);
        LI->replaceAllUsesWith(Call);

        ToErase.push_back(LI);
        collectCleanupRoot(LI->getPointerOperand(), CleanupRoots);
        Changed = true;
        continue;
      }

      if (auto *SI = dyn_cast<StoreInst>(&I))
      {
        Value *Val = SI->getValueOperand();
        Type *Ty = Val->getType();
        if (!Ty->isIntegerTy())
          continue;

        unsigned Bits = Ty->getScalarSizeInBits();
        if (Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64)
          continue;

        IRBuilder<> B(SI);
        auto Addr = tryBuildRAMAddress(SI->getPointerOperand(), RAM, DL, B, I64Ty);
        if (!Addr)
          continue;

        B.CreateCall(getWriteFunc(Bits), {*Addr, Val});
        ToErase.push_back(SI);
        collectCleanupRoot(SI->getPointerOperand(), CleanupRoots);
        Changed = true;
        continue;
      }

      if (auto *MSI = dyn_cast<MemSetInst>(&I))
      {
        IRBuilder<> B(MSI);
        auto DstAddr = tryBuildRAMAddress(MSI->getDest(), RAM, DL, B, I64Ty);
        if (!DstAddr)
          continue;

        Value *Byte = B.CreateZExtOrTrunc(MSI->getValue(), I8Ty);
        Value *Len = castUnsignedToI64(B, MSI->getLength(), I64Ty);
        B.CreateCall(MemSetFunc, {*DstAddr, Byte, Len});

        ToErase.push_back(MSI);
        collectCleanupRoot(MSI->getDest(), CleanupRoots);
        Changed = true;
        continue;
      }

      if (auto *MCI = dyn_cast<MemCpyInst>(&I))
      {
        IRBuilder<> B(MCI);
        auto DstAddr = tryBuildRAMAddress(MCI->getDest(), RAM, DL, B, I64Ty);
        if (!DstAddr)
          continue;

        auto SrcAddr = tryBuildRAMAddress(MCI->getSource(), RAM, DL, B, I64Ty);
        if (!SrcAddr)
          continue;

        Value *Len = castUnsignedToI64(B, MCI->getLength(), I64Ty);
        B.CreateCall(MemCpyFunc, {*DstAddr, *SrcAddr, Len});

        ToErase.push_back(MCI);
        collectCleanupRoot(MCI->getDest(), CleanupRoots);
        collectCleanupRoot(MCI->getSource(), CleanupRoots);
        Changed = true;
        continue;
      }

      if (auto *MMI = dyn_cast<MemMoveInst>(&I))
      {
        IRBuilder<> B(MMI);
        auto DstAddr = tryBuildRAMAddress(MMI->getDest(), RAM, DL, B, I64Ty);
        if (!DstAddr)
          continue;

        auto SrcAddr = tryBuildRAMAddress(MMI->getSource(), RAM, DL, B, I64Ty);
        if (!SrcAddr)
          continue;

        Value *Len = castUnsignedToI64(B, MMI->getLength(), I64Ty);
        B.CreateCall(MemMoveFunc, {*DstAddr, *SrcAddr, Len});

        ToErase.push_back(MMI);
        collectCleanupRoot(MMI->getDest(), CleanupRoots);
        collectCleanupRoot(MMI->getSource(), CleanupRoots);
        Changed = true;
      }
    }
  }

  for (Instruction *I : ToErase)
    I->eraseFromParent();

  for (Instruction *Root : CleanupRoots)
  {
    if (Root->getParent())
      RecursivelyDeleteTriviallyDeadInstructions(Root);
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
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
