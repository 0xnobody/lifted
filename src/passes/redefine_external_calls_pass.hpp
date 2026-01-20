#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

struct RedefineExternalCallsPass : public llvm::PassInfoMixin<RedefineExternalCallsPass>
{
    const llvm::Module &defs_module;
    std::set<llvm::Function *> externals_for_redefinition;

    RedefineExternalCallsPass(const llvm::Module &defs_module,
                              const std::set<llvm::Function *> &externals_for_redefinition)
        : defs_module(defs_module), externals_for_redefinition(externals_for_redefinition)
    {
    }

    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
};