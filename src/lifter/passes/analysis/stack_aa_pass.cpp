//===- LiftedCodeAA.cpp - Custom Alias Analysis for Lifted Code ----------===//
//
// Implementation of custom alias analysis
//
//===----------------------------------------------------------------------===//

#include "stack_aa_pass.hpp"

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/Operator.h"

#define DEBUG_TYPE "lifted-code-aa"

#define VERBOSE

using namespace llvm;

// Rules:
// 1) iA:[RAM + X + C] noalias iB:[RAM + X + D] if C and D are disjoint
// E.g.:
// %x = GEP(RAM, rax + 0x40)
// %y = GEP(RAM, rax + 0x80)
// iA:[RAM + rax + 0x40] noalias iB:[RAM + rax + 0x80]
//
// 2) iA:[RAM + X] noalias iB:[Y] where Y does not depend on RAM
// E.g.:
// %x = GEP(RAM, rax + 0x40)
// %y = GEP(rax, 0)
// iA:[RAM + rax + 0x40] noalias iB:[rax]
//
// 3) iA:[RAM + rsp + X] noalias iB:[RAM + Y] where Y is not derived from rsp
// E.g.:
// %x = GEP(RAM, rsp + 0x40)
// %y = GEP(RAM, rax + 0x80)
// iA:[RAM + rsp + 0x40] noalias iB:[RAM
//
// %x = GEP(RAM, rsp + 0x20)
// %y = GEP(RAM, rax + 0x20)
// iA:[RAM + rsp + 0x20] noalias iB:[RAM + rax + 0x20]
//
// %x = GEP(RAM, rsp + 0x20)
// %y = GEP(RAM, 0x4000)
// iA:[RAM + rsp + 0x20] noalias iB:[RAM + 0x4000]

bool isStackPointer(const Value *V)
{
    if (V == nullptr)
        return false;

    // Check if this is the rsp parameter or derived from it
    // In remill, rsp is typically a function argument
    if (const Argument *Arg = dyn_cast<Argument>(V))
    {
        return Arg->getName().contains("rsp");
    }
    return false;
}

bool isRAMPointer(const Value *V)
{
    if (V == nullptr)
        return false;

    if (const GlobalVariable *GV = dyn_cast<GlobalVariable>(V))
    {
        return GV->getName().contains("RAM");
    }
    return false;
}

// TODO: this is terrible
bool decomposeGEP(const GEPOperator *GEP, const DataLayout &DL, const Value *&Base, APInt &Offset)
{
    if (GEP->accumulateConstantOffset(DL, Offset))
    {
        Base = nullptr;
        return true;
    }

    auto offset = GEP->getOperand(2);

    // match %offset = add X, C
    if (auto *BinOp = dyn_cast<BinaryOperator>(offset))
    {
        if (BinOp->getOpcode() == Instruction::Add)
        {
            if (auto *ConstOp = dyn_cast<ConstantInt>(BinOp->getOperand(1)))
            {
                Offset = ConstOp->getValue();
                Base = BinOp->getOperand(0);
                return true;
            }
        }
    }

    return false;
}

// Conservative check: returns true if value might be derived from stack
bool mayBeDerivedFromStack(const Value *V)
{
    if (V == nullptr)
        return false;

    SmallPtrSet<const Value *, 16> Visited;
    SmallVector<const Value *, 16> Worklist;
    Worklist.push_back(V);

    while (!Worklist.empty())
    {
        const Value *Current = Worklist.pop_back_val();
        if (!Visited.insert(Current).second)
            continue;

        // TODO: think if this is ok
        if (isStackPointer(Current))
            return true;

        // Trace through arithmetic and casts
        if (auto *BinOp = dyn_cast<BinaryOperator>(Current))
        {
            Worklist.push_back(BinOp->getOperand(0));
            Worklist.push_back(BinOp->getOperand(1));
        }
        else if (auto *Cast = dyn_cast<CastInst>(Current))
        {
            Worklist.push_back(Cast->getOperand(0));
        }
        else if (isa<PHINode>(Current) || isa<SelectInst>(Current))
        {
            // Conservative: PHI/Select might merge stack and non-stack
            return true;
        }
    }

    return false; // Provably not derived from stack
}

AliasResult aliasRAMAccesses(const DataLayout &DL, const GEPOperator *GEPA, LocationSize SizeA,
                             const GEPOperator *GEPB, LocationSize SizeB)
{
    // Decompose: GEP(RAM, X + C) into (base=X, offset=C)
    const Value *BaseA;
    APInt OffsetA(64, 0);
    const Value *BaseB;
    APInt OffsetB(64, 0);

    if (!decomposeGEP(GEPA, DL, BaseA, OffsetA) ||
        !decomposeGEP(GEPB, DL, BaseB, OffsetB))
        return AliasResult::MayAlias;

#ifdef VERBOSE
    dbgs() << "Decomposed GEP A: Base=";
    if (BaseA)
        dbgs() << *BaseA;
    else
        dbgs() << "nullptr";
    dbgs() << ", Offset=" << OffsetA << "\n";

    dbgs() << "Decomposed GEP B: Base=";
    if (BaseB)
        dbgs() << *BaseB;
    else
        dbgs() << "nullptr";
    dbgs() << ", Offset=" << OffsetB << "\n";
#endif

    // Rule 1: Same base, disjoint constant offsets
    if (BaseA == BaseB && SizeA.hasValue() && SizeB.hasValue())
    {
        uint64_t EndA = OffsetA.getZExtValue() + SizeA.getValue();
        uint64_t EndB = OffsetB.getZExtValue() + SizeB.getValue();
        uint64_t StartA = OffsetA.getZExtValue();
        uint64_t StartB = OffsetB.getZExtValue();

        // Check if ranges [StartA, EndA) and [StartB, EndB) are disjoint
        if (EndA <= StartB || EndB <= StartA)
        {
#ifdef VERBOSE
            dbgs() << "NoAlias by Rule 1 (disjoint offsets)\n";
#endif
            return AliasResult::NoAlias;
        }
    }

    // Rule 3 (CONSERVATIVE): Stack vs non-stack
    // Only apply if we can prove BaseB is NOT derived from rsp
    if (isStackPointer(BaseA) && !mayBeDerivedFromStack(BaseB))
    {
        // Additional safety: check that BaseB is not a PHI or Select
        // that could merge stack and non-stack pointers
#ifdef VERBOSE
        dbgs() << "NoAlias by Rule 3 (stack vs non-stack)\n";
#endif
        return AliasResult::NoAlias;
    }
    if (isStackPointer(BaseB) && !mayBeDerivedFromStack(BaseA))
    {
#ifdef VERBOSE
        dbgs() << "NoAlias by Rule 3 (stack vs non-stack)\n";
#endif
        return AliasResult::NoAlias;
    }

    // TODO: reg value vs global? reg value vs stack? etc.

    return AliasResult::MayAlias;
}

AliasResult LiftedCodeAAResult::alias(const MemoryLocation &LocA,
                                      const MemoryLocation &LocB,
                                      AAQueryInfo &AAQI,
                                      const Instruction *CtxI)
{
    const DataLayout &DL = CtxI->getModule()->getDataLayout();

    const Value *PtrA = LocA.Ptr->stripPointerCasts();
    const Value *PtrB = LocB.Ptr->stripPointerCasts();

#ifdef VERBOSE
    dbgs() << "LiftedCodeAA alias query:\n";
    dbgs() << *PtrA << "\n";
    dbgs() << *PtrB << "\n";
#endif

    // Rule 4 & 5: State vs State and State vs RAM
    if (auto *GEPA = dyn_cast<GEPOperator>(PtrA))
    {
        if (auto *GEPB = dyn_cast<GEPOperator>(PtrB))
        {
            auto BaseA = GEPA->getPointerOperand()->stripPointerCasts();
            auto BaseB = GEPB->getPointerOperand()->stripPointerCasts();

            auto BaseARAM = isRAMPointer(BaseA);
            auto BaseBRAM = isRAMPointer(BaseB);

            if (BaseARAM ^ BaseBRAM)
                return AliasResult::NoAlias;

            // Both are RAM: decompose further
            if (BaseARAM && BaseBRAM)
            {
                return aliasRAMAccesses(DL, GEPA, LocA.Size, GEPB, LocA.Size);
            }
        }
    }

    return AAResultBase::alias(LocA, LocB, AAQI, CtxI);
}

AnalysisKey LiftedCodeAA::Key;

LiftedCodeAAResult LiftedCodeAA::run(Function &F,
                                     FunctionAnalysisManager &AM)
{
    return LiftedCodeAAResult(F.getParent()->getDataLayout());
}
