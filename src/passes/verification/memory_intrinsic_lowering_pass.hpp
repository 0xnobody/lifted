#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

struct MemoryIntrinsicLoweringPass : public llvm::PassInfoMixin<MemoryIntrinsicLoweringPass> {
  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
};