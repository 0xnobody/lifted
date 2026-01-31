#pragma once

#include <llvm/IR/Module.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace lifted::opt
{

  void always_inline(llvm::Module *M);
  void default_opt(llvm::Module *M, llvm::OptimizationLevel level = llvm::OptimizationLevel::O3);
  void default_opt(llvm::Function &F, llvm::OptimizationLevel level = llvm::OptimizationLevel::O3);

  template <typename T>
  void run_pass(llvm::Module *M)
  {
    llvm::PassBuilder PB;
    llvm::LoopAnalysisManager LAM;
    llvm::FunctionAnalysisManager FAM;
    llvm::CGSCCAnalysisManager CGAM;
    llvm::ModuleAnalysisManager MAM;

    PB.registerModuleAnalyses(MAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    llvm::FunctionPassManager FPM;
    FPM.addPass(T());

    llvm::ModulePassManager MPM;
    MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));

    MPM.run(*M, MAM);
  }

  template <typename FuncPassT, typename... CtorArgs>
  llvm::PreservedAnalyses run_pass(
      llvm::Function &F,
      CtorArgs &&...args)
  {

    using namespace llvm;

    // New PM managers
    PassBuilder PB;
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;

    // Register standard analyses
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    // Build and run the function pipeline
    FunctionPassManager FPM;
    FPM.addPass(FuncPassT(std::forward<CtorArgs>(args)...));
    return FPM.run(F, FAM);
  }

}