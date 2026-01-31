#pragma once

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

//===----------------------------------------------------------------------===//
// LiftedCodeAAResult - The actual alias analysis implementation
//===----------------------------------------------------------------------===//

class LiftedCodeAAResult : public llvm::AAResultBase
{
    const llvm::DataLayout &DL;

public:
    explicit LiftedCodeAAResult(const llvm::DataLayout &DL) : AAResultBase(), DL(DL) {}

    LiftedCodeAAResult(LiftedCodeAAResult &&Arg)
        : AAResultBase(std::move(Arg)), DL(Arg.DL) {}

    /// Handle alias queries between two memory locations
    llvm::AliasResult alias(const llvm::MemoryLocation &LocA, const llvm::MemoryLocation &LocB,
                            llvm::AAQueryInfo &AAQI, const llvm::Instruction *CtxI);

private:
    /// Your custom analysis logic helpers
    bool isKnownNoAlias(const llvm::Value *PtrA, const llvm::Value *PtrB);
};

class LiftedCodeAA : public llvm::AnalysisInfoMixin<LiftedCodeAA>
{
    friend llvm::AnalysisInfoMixin<LiftedCodeAA>;
    static llvm::AnalysisKey Key;

public:
    typedef LiftedCodeAAResult Result;

    LiftedCodeAAResult run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);
};
