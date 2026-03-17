#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/ADT/AddressRanges.h>

#include <set>
#include <optional>

namespace LIEF
{
    class Binary;
}

namespace llvm
{
    class LoadInst;
    class Constant;
}

struct ConstantMemoryFoldingPass : public llvm::PassInfoMixin<ConstantMemoryFoldingPass>
{
private:
    const LIEF::Binary &Binary;
    const std::set<llvm::AddressRange> &ConstMemoryRvaRanges;

    bool isInConstMemoryRange(uint64_t RVA) const;
    bool isElfGotAddress(uint64_t RVA) const;
    bool isFoldableAddress(uint64_t RVA) const;
    std::optional<uint64_t> tryGetConstantAddress(llvm::GEPOperator *GEP, llvm::Module *M) const;

    struct SelectInfo
    {
        llvm::SelectInst *SI;
        llvm::GEPOperator *GEP;
        uintptr_t TrueRVA;
        uintptr_t FalseRVA;
    };
    std::optional<SelectInfo> tryGetConstantAddressSelect(llvm::GEPOperator *GEP) const;

    struct SelectBasedIndexInfo
    {
        llvm::SelectInst *RootSelect;                         // The select at the root of the index computation
        llvm::GEPOperator *GEP;                               // The GEP using this index
        llvm::SmallVector<llvm::Instruction *, 8> IndexChain; // Chain from select to GEP index
        uint64_t TrueRVA;                                     // Computed RVA when select takes true path
        uint64_t FalseRVA;                                    // Computed RVA when select takes false path
    };
    std::optional<SelectBasedIndexInfo> analyzeSelectBasedIndex(llvm::GEPOperator *GEP, llvm::Module *M) const;
    bool replaceLoadWithSelectHoist(llvm::LoadInst *LI, const SelectBasedIndexInfo &Info);

    llvm::Constant *extractConstantFromRVA(uint64_t RVA, llvm::Type *Ty);

    bool replaceLoadWithConstant(llvm::LoadInst *LI, uint64_t RVA);
    bool replaceLoadWithConstantSelect(llvm::LoadInst *LI, const SelectInfo &SInfo);

public:
    ConstantMemoryFoldingPass(const LIEF::Binary &Binary,
                              const std::set<llvm::AddressRange> &ConstMemoryRvaRanges)
        : Binary(Binary), ConstMemoryRvaRanges(ConstMemoryRvaRanges)
    {
    }

    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
};