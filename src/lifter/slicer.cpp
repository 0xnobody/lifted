
#include "slicer.hpp"

#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

namespace lifted::slicer
{
    using namespace llvm;

    /*
    // Helper function to check control dependence
    bool hasControlDependence(BasicBlock *A, BasicBlock *B,
                              PostDominatorTree &PDT)
    {
        if (PDT.dominates(B, A))
            return false;

        Instruction *Term = A->getTerminator();
        if (Term->getNumSuccessors() < 2)
            return false;

        bool postDomsSome = false;
        bool notPostDomsAll = false;

        for (BasicBlock *Succ : successors(A))
        {
            if (PDT.dominates(B, Succ))
            {
                postDomsSome = true;
            }
            else
            {
                notPostDomsAll = true;
            }
        }

        return postDomsSome && notPostDomsAll;
    }

    // Helper to add memory access to worklist
    void addMemoryAccessToWorklist(MemoryAccess *MA,
                                   SmallVectorImpl<Value *> &Worklist,
                                   SmallPtrSetImpl<Value *> &Visited)
    {
        if (!MA)
            return;

        // Handle MemoryPhi nodes
        if (MemoryPhi *MPhi = dyn_cast<MemoryPhi>(MA))
        {
            for (unsigned i = 0; i < MPhi->getNumIncomingValues(); ++i)
            {
                MemoryAccess *Incoming = MPhi->getIncomingValue(i);
                addMemoryAccessToWorklist(Incoming, Worklist, Visited);
            }
            return;
        }

        // MemoryUseOrDef has getMemoryInst() method
        if (MemoryUseOrDef *MUD = dyn_cast<MemoryUseOrDef>(MA))
        {
            if (Instruction *MemInst = MUD->getMemoryInst())
            {
                if (Visited.insert(MemInst).second)
                {
                    Worklist.push_back(MemInst);
                }
            }
        }
    }

    // Main slicing function
    SmallPtrSet<Instruction *, 32>
    computeBackwardSlice(Value *Target,
                         MemorySSA &MSSA,
                         PostDominatorTree &PDT,
                         DominatorTree &DT)
    {

        SmallPtrSet<Instruction *, 32> SliceInstructions;
        SmallVector<Value *, 32> Worklist;
        SmallPtrSet<Value *, 32> Visited;

        Worklist.push_back(Target);
        Visited.insert(Target);

        MemorySSAWalker *Walker = MSSA.getWalker();

        while (!Worklist.empty())
        {
            Value *Current = Worklist.pop_back_val();

            Instruction *I = dyn_cast<Instruction>(Current);
            if (!I)
                continue;

            SliceInstructions.insert(I);

            // Step 1: Data Dependencies
            for (Use &Op : I->operands())
            {
                Value *OpVal = Op.get();
                if (Visited.insert(OpVal).second)
                {
                    Worklist.push_back(OpVal);
                }
            }

            // Step 2: Memory Dependencies
            if (I->mayReadFromMemory() || I->mayWriteToMemory())
            {
                MemoryAccess *MA = MSSA.getMemoryAccess(I);

                // Only process MemoryUse (loads) - they depend on stores
                if (MemoryUse *MU = dyn_cast_or_null<MemoryUse>(MA))
                {
                    MemoryAccess *Clobber = Walker->getClobberingMemoryAccess(MU);
                    addMemoryAccessToWorklist(Clobber, Worklist, Visited);
                }
                // Don't process MemoryDef (stores) for backward slicing
                // Stores don't have memory dependencies in the backward direction
            }

            // Step 3: Control Dependencies
            BasicBlock *BB = I->getParent();
            Function *F = BB->getParent();

            for (BasicBlock &PredBB : *F)
            {
                if (hasControlDependence(&PredBB, BB, PDT))
                {
                    Instruction *Term = PredBB.getTerminator();
                    if (Visited.insert(Term).second)
                    {
                        Worklist.push_back(Term);
                    }
                }
            }
        }

        return SliceInstructions;
    }
    */

    // Helper function to check control dependence (unchanged from your version)
    bool hasControlDependence(BasicBlock *A, BasicBlock *B,
                              PostDominatorTree &PDT)
    {
        if (PDT.dominates(B, A))
            return false;

        Instruction *Term = A->getTerminator();
        if (Term->getNumSuccessors() < 2)
            return false;

        bool postDomsSome = false;
        bool notPostDomsAll = false;

        for (BasicBlock *Succ : successors(A))
        {
            if (PDT.dominates(B, Succ))
            {
                postDomsSome = true;
            }
            else
            {
                notPostDomsAll = true;
            }
        }

        return postDomsSome && notPostDomsAll;
    }

    // Helper to add memory access to worklist (unchanged)
    void addMemoryAccessToWorklist(MemoryAccess *MA,
                                   SmallVectorImpl<Value *> &Worklist,
                                   SmallPtrSetImpl<Value *> &Visited)
    {
        if (!MA)
            return;

        if (MemoryPhi *MPhi = dyn_cast<MemoryPhi>(MA))
        {
            for (unsigned i = 0; i < MPhi->getNumIncomingValues(); ++i)
            {
                MemoryAccess *Incoming = MPhi->getIncomingValue(i);
                addMemoryAccessToWorklist(Incoming, Worklist, Visited);
            }
            return;
        }

        if (MemoryUseOrDef *MUD = dyn_cast<MemoryUseOrDef>(MA))
        {
            if (Instruction *MemInst = MUD->getMemoryInst())
            {
                if (Visited.insert(MemInst).second)
                {
                    Worklist.push_back(MemInst);
                }
            }
        }
    }

    // Helper to ensure control flow is preserved
    void addRequiredControlFlowBlocks(SliceResult &Result,
                                      SmallPtrSetImpl<BasicBlock *> &ControlDeps,
                                      DominatorTree &DT)
    {
        // For each block in the slice, ensure dominators are included
        // to maintain control flow reachability
        SmallVector<BasicBlock *, 16> BlocksToProcess(Result.SlicedBlocks.begin(),
                                                      Result.SlicedBlocks.end());

        for (size_t i = 0; i < BlocksToProcess.size(); ++i)
        {
            BasicBlock *BB = BlocksToProcess[i];

            // Add dominators to ensure CFG connectivity
            DomTreeNode *Node = DT.getNode(BB);
            while (Node)
            {
                BasicBlock *DomBB = Node->getBlock();
                if (Result.SlicedBlocks.insert(DomBB).second)
                {
                    // Add terminator of newly added blocks
                    Instruction *Term = DomBB->getTerminator();
                    Result.SlicedInstructions.insert(Term);
                    BlocksToProcess.push_back(DomBB);
                }
                Node = Node->getIDom();
            }
        }

        // Add terminators of control-dependent blocks
        for (BasicBlock *BB : ControlDeps)
        {
            Result.SlicedBlocks.insert(BB);
            Result.SlicedInstructions.insert(BB->getTerminator());
        }
    }

    // Main slicing function - returns SliceResult with structural information
    SliceResult computeBackwardSlice(Value *Target,
                                     MemorySSA &MSSA,
                                     PostDominatorTree &PDT,
                                     DominatorTree &DT)
    {
        SliceResult Result;
        SmallVector<Value *, 32> Worklist;
        SmallPtrSet<Value *, 32> Visited;
        SmallPtrSet<BasicBlock *, 16> ControlDependentBlocks;

        Worklist.push_back(Target);
        Visited.insert(Target);

        MemorySSAWalker *Walker = MSSA.getWalker();

        while (!Worklist.empty())
        {
            Value *Current = Worklist.pop_back_val();

            Instruction *I = dyn_cast<Instruction>(Current);
            if (!I)
                continue;

            Result.SlicedInstructions.insert(I);
            Result.SlicedBlocks.insert(I->getParent());

            // Step 1: Data Dependencies
            for (Use &Op : I->operands())
            {
                Value *OpVal = Op.get();
                if (Visited.insert(OpVal).second)
                {
                    Worklist.push_back(OpVal);
                }
            }

            // Step 2: Memory Dependencies
            if (I->mayReadFromMemory() || I->mayWriteToMemory())
            {
                MemoryAccess *MA = MSSA.getMemoryAccess(I);

                if (MemoryUse *MU = dyn_cast_or_null<MemoryUse>(MA))
                {
                    MemoryAccess *Clobber = Walker->getClobberingMemoryAccess(MU);
                    addMemoryAccessToWorklist(Clobber, Worklist, Visited);
                }
            }

            // Step 3: Control Dependencies
            BasicBlock *BB = I->getParent();
            Function *F = BB->getParent();

            for (BasicBlock &PredBB : *F)
            {
                if (hasControlDependence(&PredBB, BB, PDT))
                {
                    Instruction *Term = PredBB.getTerminator();
                    if (Visited.insert(Term).second)
                    {
                        Worklist.push_back(Term);
                    }
                    ControlDependentBlocks.insert(&PredBB);
                }
            }
        }

        // Step 4: Add necessary basic blocks for control flow connectivity
        // We need to ensure that the slice maintains a valid CFG structure
        addRequiredControlFlowBlocks(Result, ControlDependentBlocks, DT);

        return Result;
    }

    // 1. Compute Slice for Return Value(s)
    //    Aggregates slices from all ReturnInsts in the function.
    SliceResult computeBackwardSliceForReturn(Function &F,
                                              MemorySSA &MSSA,
                                              PostDominatorTree &PDT,
                                              DominatorTree &DT)
    {
        SliceResult CombinedResult;

        // Find all return instructions
        SmallVector<ReturnInst *, 4> Returns;
        for (BasicBlock &BB : F)
        {
            if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            {
                Returns.push_back(RI);
            }
        }

        // Compute slice for each return and merge results
        for (ReturnInst *RI : Returns)
        {
            // The ReturnInst itself is the starting point (the sink)
            SliceResult Res = computeBackwardSlice(RI, MSSA, PDT, DT);

            CombinedResult.SlicedInstructions.insert(
                Res.SlicedInstructions.begin(), Res.SlicedInstructions.end());
            CombinedResult.SlicedBlocks.insert(
                Res.SlicedBlocks.begin(), Res.SlicedBlocks.end());
        }

        return CombinedResult;
    }

    // 2. Compute Slice and Clone Function
    //    Creates a new function containing ONLY the sliced instructions/blocks.
    Function *computeBackwardSliceForReturnClone(Function &F,
                                                 MemorySSA &MSSA,
                                                 PostDominatorTree &PDT,
                                                 DominatorTree &DT)
    {

        // Step 1: Get the slice
        SliceResult Slice = computeBackwardSliceForReturn(F, MSSA, PDT, DT);

        // Step 2: Create the new empty function
        // We keep the same function type/signature
        Function *NewF = Function::Create(
            F.getFunctionType(),
            F.getLinkage(),
            F.getName() + ".sliced",
            F.getParent() // Add to same module
        );

        // Map from Old Value -> New Value
        ValueToValueMapTy VMap;

        // Step 3: Map Arguments
        auto NewArgIt = NewF->arg_begin();
        for (auto &Arg : F.args())
        {
            VMap[&Arg] = &*NewArgIt++;
        }

        // Step 4: Create New Basic Blocks
        // We only create blocks that are present in the slice
        for (BasicBlock *OldBB : Slice.SlicedBlocks)
        {
            BasicBlock *NewBB = BasicBlock::Create(F.getContext(), OldBB->getName(), NewF);
            VMap[OldBB] = NewBB;
        }

        // Step 5: Clone Instructions
        for (BasicBlock *OldBB : Slice.SlicedBlocks)
        {
            BasicBlock *NewBB = cast<BasicBlock>(VMap[OldBB]);

            for (Instruction &I : *OldBB)
            {
                // Only clone if it's in the slice
                if (Slice.containsInstruction(&I))
                {
                    Instruction *NewI = I.clone();
                    NewI->insertInto(NewBB, NewBB->end());
                    VMap[&I] = NewI;
                }
            }
        }

        // Step 6: Remap Operands and Fix PHIs
        for (Function::iterator BB = NewF->begin(); BB != NewF->end(); ++BB)
        {
            for (Instruction &I : *BB)
            {
                // Remap operands (uses VMap to point to new instructions/blocks)
                RemapInstruction(&I, VMap, RF_None | RF_IgnoreMissingLocals);

                // Fix PHI Nodes:
                // If a PHI node has an incoming block that wasn't included in the slice,
                // that incoming edge is now invalid. We must remove it.
                if (PHINode *PN = dyn_cast<PHINode>(&I))
                {
                    for (int i = PN->getNumIncomingValues() - 1; i >= 0; --i)
                    {
                        BasicBlock *IncomingBB = PN->getIncomingBlock(i);
                        // If the old incoming block was not sliced, it wasn't mapped.
                        if (VMap.find(IncomingBB) == VMap.end())
                        {
                            PN->removeIncomingValue(i, false);
                        }
                    }
                }
            }
        }

        // Step 7: Handle Missing Terminators
        // If a block was sliced but its terminator wasn't (e.g., irrelevant control flow),
        // the new block will be malformed. We insert 'unreachable' to seal it.
        for (Function::iterator BB = NewF->begin(); BB != NewF->end(); ++BB)
        {
            if (!BB->getTerminator())
            {
                new UnreachableInst(F.getContext(), &*BB);
            }
        }

        return NewF;
    }
}
