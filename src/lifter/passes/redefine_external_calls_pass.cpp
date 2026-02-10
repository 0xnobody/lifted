// redefine_external_calls_pass.cpp
// Rewrites calls to external functions by extracting ABI arguments from
// Remill's State struct and calling user-provided redefinitions.
//
// This pass uses the shared ABI utilities from abi/abi_utils.hpp for
// register extraction, casting, and return value writeback.

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
#include "../abi/abi_utils.hpp"
#include "../abi/systemv_x64.hpp"

using namespace llvm;

struct ExternalFuncDef
{
    Function *CallStub;
    Function *Redefinition;

    llvm::SmallVector<CallInst *, 8> CallSites;
};

PreservedAnalyses RedefineExternalCallsPass::run(Function &F, FunctionAnalysisManager &)
{
    Module *M = F.getParent();
    LLVMContext &Ctx = M->getContext();

    // TODO: Make the calling convention configurable via the pass constructor.
    lifted::abi::SystemVx64CC CC;

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

        // Use shared ABI utilities: extract args, call, write return, clobber, pop ret addr.
        lifted::abi::EmitCall(Builder, CC, Ext.second.Redefinition, State, Memory);

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
