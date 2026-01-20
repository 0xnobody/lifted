#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

struct CanonicalizeStackPass : public llvm::PassInfoMixin<CanonicalizeStackPass> {
  // Configuration
  static constexpr unsigned StackAlignBytes = 16;

  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
};