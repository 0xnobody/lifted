
#include "opt.hpp"

#include <llvm/IR/Module.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace lifted::opt
{

void always_inline(llvm::Module *M)
{
    // Set up all the analysis managers
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

    // Build the module‐level pipeline
    auto MPM = llvm::ModulePassManager();
    MPM.addPass(llvm::AlwaysInlinerPass());

    // Run it
    MPM.run(*M, MAM);
}

void default_opt(llvm::Module *M, llvm::OptimizationLevel level)
{
    // Set up all the analysis managers
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

    // Build the module‐level pipeline
    auto MPM = PB.buildPerModuleDefaultPipeline(level);

    // Run it
    MPM.run(*M, MAM);
}

void default_opt(llvm::Function &F, llvm::OptimizationLevel level) {
    using namespace llvm;

    // Create analysis managers
    LoopAnalysisManager LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager CGAM;
    ModuleAnalysisManager MAM;
    PassBuilder PB;

    // Register all standard analyses
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    // Build the per-function optimization pipeline
    FunctionPassManager FPM = PB.buildFunctionSimplificationPipeline(level,
                                                                     ThinOrFullLTOPhase::None);

    // Run it
    FPM.run(F, FAM);
}

}