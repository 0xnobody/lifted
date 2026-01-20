#pragma once

#include <llvm/ADT/SmallPtrSet.h>
#include "llvm/Analysis/PostDominators.h"
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/Analysis/MemorySSA.h>
#include <llvm/Analysis/TargetLibraryInfo.h>

namespace llvm
{
    class Value;
    class Function;
    class Instruction;
    class AAResults;
}

namespace lifted::slicer
{
    // Structure to hold slice results with control flow information
    struct SliceResult
    {
        llvm::SmallPtrSet<llvm::Instruction *, 32> SlicedInstructions;
        llvm::SmallPtrSet<llvm::BasicBlock *, 16> SlicedBlocks;

        bool containsInstruction(llvm::Instruction *I) const
        {
            return SlicedInstructions.count(I);
        }

        bool containsBlock(llvm::BasicBlock *BB) const
        {
            return SlicedBlocks.count(BB);
        }
    };

    SliceResult computeBackwardSlice(llvm::Value *Target,
                                     llvm::MemorySSA &MSSA,
                                     llvm::PostDominatorTree &PDT,
                                     llvm::DominatorTree &DT);

    SliceResult computeBackwardSliceForReturn(llvm::Function &F,
                                              llvm::MemorySSA &MSSA,
                                              llvm::PostDominatorTree &PDT,
                                              llvm::DominatorTree &DT);

    llvm::Function *computeBackwardSliceForReturnClone(llvm::Function &F,
                                                       llvm::MemorySSA &MSSA,
                                                       llvm::PostDominatorTree &PDT,
                                                       llvm::DominatorTree &DT);
    template <typename... AAResultTs>
    SliceResult
    computeBackwardSlice(llvm::Value *Target, llvm::Function &F, AAResultTs &...CustomAAs)
    {
        // Build required analyses
        llvm::DominatorTree DT(F);
        llvm::PostDominatorTree PDT(F);

        // Create TargetLibraryInfo for AAResults
        llvm::Triple TargetTriple(F.getParent()->getTargetTriple());
        llvm::TargetLibraryInfoImpl TLII(TargetTriple);
        llvm::TargetLibraryInfo TLI(TLII);

        // Build AAResults with TargetLibraryInfo
        llvm::AAResults AA(TLI);

        // Add all custom AA results to the chain
        // Fold expression (C++17) to add each AA
        (AA.addAAResult(CustomAAs), ...);

        // Build MemorySSA
        llvm::MemorySSA MSSA(F, &AA, &DT);

        return computeBackwardSlice(Target, MSSA, PDT, DT);
    }

    template <typename... AAResultTs>
    SliceResult
    computeBackwardSliceForReturn(llvm::Function &F, AAResultTs &...CustomAAs)
    {
        // Build required analyses
        llvm::DominatorTree DT(F);
        llvm::PostDominatorTree PDT(F);

        // Create TargetLibraryInfo for AAResults
        llvm::Triple TargetTriple(F.getParent()->getTargetTriple());
        llvm::TargetLibraryInfoImpl TLII(TargetTriple);
        llvm::TargetLibraryInfo TLI(TLII);

        // Build AAResults with TargetLibraryInfo
        llvm::AAResults AA(TLI);

        // Add all custom AA results to the chain
        // Fold expression (C++17) to add each AA
        (AA.addAAResult(CustomAAs), ...);

        // Build MemorySSA
        llvm::MemorySSA MSSA(F, &AA, &DT);

        return computeBackwardSliceForReturn(F, MSSA, PDT, DT);
    }

    template <typename... AAResultTs>
    llvm::Function *
    computeBackwardSliceForReturnClone(llvm::Function &F, AAResultTs &...CustomAAs)
    {
        // Build required analyses
        llvm::DominatorTree DT(F);
        llvm::PostDominatorTree PDT(F);

        // Create TargetLibraryInfo for AAResults
        llvm::Triple TargetTriple(F.getParent()->getTargetTriple());
        llvm::TargetLibraryInfoImpl TLII(TargetTriple);
        llvm::TargetLibraryInfo TLI(TLII);

        // Build AAResults with TargetLibraryInfo
        llvm::AAResults AA(TLI);

        // Add all custom AA results to the chain
        // Fold expression (C++17) to add each AA
        (AA.addAAResult(CustomAAs), ...);

        // Build MemorySSA
        llvm::MemorySSA MSSA(F, &AA, &DT);

        return computeBackwardSliceForReturnClone(F, MSSA, PDT, DT);
    }
}