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

#include "redefine_external_calls_pass.hpp"

using namespace llvm;

struct ExternalFuncDef
{
    Function *CallStub;
    Function *Redefinition;

    llvm::SmallVector<CallInst *, 8> CallSites;
};

enum class ABIRegister
{
    RDI,
    RSI,
    RDX,
    RCX,
    R8,
    R9,
    RSP
};

Value *GetRegisterValue(ABIRegister Reg, Value *State, IRBuilder<> &Builder)
{
    switch (Reg)
    {
    case ABIRegister::RDI:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_rdi"), {State});
    case ABIRegister::RSI:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_rsi"), {State});
    case ABIRegister::RDX:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_rdx"), {State});
    case ABIRegister::RCX:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_rcx"), {State});
    case ABIRegister::R8:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_r8"), {State});
    case ABIRegister::R9:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_r9"), {State});
    case ABIRegister::RSP:
        return Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__extract_rsp"), {State});
    default:
        llvm_unreachable("Unsupported ABI register");
    }
}

Value *CastToType(Value *Src, Type *DstTy, IRBuilder<> &Builder)
{
    if (Src->getType() == DstTy)
        return Src;

    auto DL = Builder.GetInsertBlock()->getModule()->getDataLayout();
    auto PtrSize = DL.getPointerSizeInBits();

    auto SrcSize = Src->getType()->getScalarSizeInBits();
    auto DstSize = DstTy->isPointerTy() ? PtrSize : DstTy->getScalarSizeInBits();

    if (SrcSize == DstSize)
    {
        return Builder.CreateBitOrPointerCast(Src, DstTy);
    }
    else if (DstTy->isIntegerTy())
    {
        if (SrcSize < DstSize)
            return Builder.CreateZExt(Src, DstTy);
        else
            return Builder.CreateTrunc(Src, DstTy);
    }
    else
    {
        llvm_unreachable("Unsupported cast type");
    }
}

void WriteRSP(Value *State, Value *RSPValue, IRBuilder<> &Builder)
{
    Builder.CreateCall(Builder.GetInsertBlock()->getModule()->getFunction("__store_rsp"), {State, RSPValue});
}

void ExtractStackArgs(IRBuilder<> &Builder, llvm::ArrayRef<Value *> StackArgs, Value *State, Value *Memory, llvm::SmallVector<Value *, 8> &CallArgs)
{
    Module *M = Builder.GetInsertBlock()->getModule();
    const DataLayout &DL = M->getDataLayout();
    LLVMContext &Ctx = M->getContext();

    Type *Int64Ty = Type::getInt64Ty(Ctx);

    for (int i = 0; i < StackArgs.size(); ++i)
    {
        Value *SP = Builder.CreateCall(M->getFunction("__extract_rsp"), {State});
        Value *ArgOffset = Builder.CreateAdd(
            SP,
            ConstantInt::get(Int64Ty, (i + 1) * DL.getPointerSize(0))); // +1 to skip return address

        Value *ArgValue = Builder.CreateCall(M->getFunction("__remill_read_memory_64"), {Memory, ArgOffset});

        CallArgs.push_back(CastToType(ArgValue, StackArgs[i]->getType(), Builder));
    }
}

void EmitCall_SystemV(IRBuilder<> &Builder, Function *Callee, Value *State, Value *Memory)
{
    llvm::SmallVector<Value *, 8> CallArgs;

    // First six integer/pointer arguments are passed in registers.
    static const ABIRegister ArgRegs[] = {
        ABIRegister::RDI,
        ABIRegister::RSI,
        ABIRegister::RDX,
        ABIRegister::RCX,
        ABIRegister::R8,
        ABIRegister::R9,
    };

    size_t NumArgs = Callee->arg_size();

    size_t NumRegArgs = std::min(NumArgs, sizeof(ArgRegs) / sizeof(ABIRegister));
    for (size_t i = 0; i < NumRegArgs; ++i)
    {
        CallArgs.push_back(CastToType(GetRegisterValue(ArgRegs[i], State, Builder), Callee->getArg(i)->getType(), Builder));
    }

    // Additional arguments are passed on the stack.
    if (NumArgs > NumRegArgs)
    {
        llvm::SmallVector<Value *, 8> StackArgs;
        for (size_t i = NumRegArgs; i < NumArgs; ++i)
        {
            StackArgs.push_back(Callee->getArg(i));
        }
        ExtractStackArgs(Builder, StackArgs, State, Memory, CallArgs);
    }

    // TODO: write back rax, rdx for return values.
    Builder.CreateCall(Callee, CallArgs);

    // Restore RSP (i.e. simulate 'ret' so our stack remains aligned)
    // If we didn't do this, each call would push a return address onto the stack.
    //
    Value *RSP = GetRegisterValue(ABIRegister::RSP, State, Builder);
    Value *NewRSP = Builder.CreateAdd(
        RSP,
        ConstantInt::get(Type::getInt64Ty(Memory->getContext()), 8)); // +8 for return address
    WriteRSP(State, NewRSP, Builder);
}

PreservedAnalyses RedefineExternalCallsPass::run(Function &F, FunctionAnalysisManager &)
{
    Module *M = F.getParent();
    LLVMContext &Ctx = M->getContext();
    const DataLayout &DL = M->getDataLayout();

    // Iterate through each external function call.
    //
    llvm::MapVector<Function *, ExternalFuncDef> ExternalFuncs;

    for (auto &BB : F)
    {
        for (auto &I : BB)
        {
            if (auto *Call = dyn_cast<CallInst>(&I))
            {
                if (Function *Callee = Call->getCalledFunction())
                {
                    if (externals_for_redefinition.contains(Callee))
                    {
                        ExternalFuncs.insert({Callee, ExternalFuncDef{}});
                        ExternalFuncs[Callee].CallSites.push_back(Call);
                    }
                }
            }
        }
    }

    for (auto &Ext : ExternalFuncs)
    {
        // Copy the redefinition function from the defs module.
        //
        Function *RedefFunc = defs_module.getFunction(Ext.first->getName());
        if (!RedefFunc)
        {
            errs() << "Warning: No redefinition found for external function: " << Ext.first->getName() << "\n";
            continue;
        }

        Ext.second.Redefinition = Function::Create(
            RedefFunc->getFunctionType(),
            RedefFunc->getLinkage(),
            RedefFunc->getName() + "_redef",
            M);

        // Emit a call stub function - which extracts arguments from the state/memory
        // and calls the redefinition function.
        //
        Function *CallStub = Function::Create(
            Ext.first->getFunctionType(),
            Function::InternalLinkage,
            Ext.first->getName() + "_callstub",
            M);

        Argument *State = CallStub->getArg(0);
        Argument *PC = CallStub->getArg(1);
        Argument *Memory = CallStub->getArg(2);

        State->addAttr(Attribute::NoAlias);
        Memory->addAttr(Attribute::NoAlias);

        // Mark as always inline.
        CallStub->addFnAttr(Attribute::AlwaysInline);
        IRBuilder<> Builder(BasicBlock::Create(Ctx, "entry", CallStub));

        EmitCall_SystemV(Builder, Ext.second.Redefinition, State, Memory);

        Builder.CreateRet(Memory);

        Ext.second.CallStub = CallStub;

        // Replace all call sites to the external function with calls to the call stub.
        //
        for (auto *CallSite : Ext.second.CallSites)
        {
            IRBuilder<> CallBuilder(CallSite);
            llvm::SmallVector<Value *, 8> CallArgs;
            for (unsigned i = 0; i < CallSite->arg_size(); ++i)
            {
                CallArgs.push_back(CallSite->getArgOperand(i));
            }
            CallBuilder.CreateCall(CallStub, CallArgs);
            CallSite->eraseFromParent();
        }
    }

    return PreservedAnalyses::none();
}
