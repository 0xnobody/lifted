#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/Analysis/DemandedBits.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"

using namespace llvm;
using namespace llvm::PatternMatch;

class WidthNormalizePass : public PassInfoMixin<WidthNormalizePass>
{
    struct Ctx
    {
        const DataLayout &DL;
        AssumptionCache &AC;
        DominatorTree &DT;
        DemandedBits &DB;
    };

    static bool isContiguousLowMask(const APInt &M, unsigned &N)
    {
        if (M.isZero())
            return false;
        N = M.countTrailingOnes();
        return M == APInt::getLowBitsSet(M.getBitWidth(), N);
    }

    static unsigned chooseTargetWidth(unsigned N, bool RoundToByte = true)
    {
        if (!RoundToByte)
            return std::max(1u, N);
        return std::max(8u, (N + 7) & ~7u);
    }

    static Value *rebuildNarrow(Value *V, unsigned WT, IRBuilder<> &B, const Ctx &C)
    {
        if (V->getType()->isIntegerTy(WT))
            return V;
        if (!V->getType()->isIntegerTy())
            return nullptr;

        Type *WTy = IntegerType::get(B.getContext(), WT);

        if (auto *LI = dyn_cast<LoadInst>(V))
        {
            IRBuilder<> BI(LI);

            Value *Ptr = LI->getPointerOperand();

            LoadInst *NewL = BI.CreateLoad(WTy, Ptr);
            NewL->setAlignment(LI->getAlign());
            NewL->setVolatile(LI->isVolatile());
            return NewL;
        }

        if (auto *ZI = dyn_cast<ZExtInst>(V))
        {
            Value *S = ZI->getOperand(0);
            if (auto *STy = dyn_cast<IntegerType>(S->getType()))
            {
                if (STy->getBitWidth() <= WT)
                {
                    Value *Sn = rebuildNarrow(S, STy->getBitWidth(), B, C);
                    return STy->getBitWidth() == WT ? Sn : B.CreateZExt(Sn, WTy);
                }
            }
        }

        if (auto *TI = dyn_cast<TruncInst>(V))
        {
            Value *S = TI->getOperand(0);
            unsigned SW = cast<IntegerType>(S->getType())->getBitWidth();
            if (WT <= TI->getType()->getIntegerBitWidth())
                return B.CreateTrunc(rebuildNarrow(S, std::min<unsigned>(SW, WT), B, C), WTy);
            // If WT > trunc target, we still can rebuild producer in WT and drop the old trunc at users.
            return B.CreateTrunc(rebuildNarrow(S, std::min<unsigned>(SW, WT), B, C), WTy);
        }

        if (auto *BO = dyn_cast<BinaryOperator>(V))
        {
            if (Value *R = narrowBinOp(BO, WT, B, C))
                return R;
        }

        if (auto *Sel = dyn_cast<SelectInst>(V))
        {
            Value *T = rebuildNarrow(Sel->getTrueValue(), WT, B, C);
            Value *F = rebuildNarrow(Sel->getFalseValue(), WT, B, C);
            if (!T || !F)
                return nullptr;
            return B.CreateSelect(Sel->getCondition(), T, F);
        }

        if (auto *Phi = dyn_cast<PHINode>(V))
        {
            PHINode *NewPhi = B.CreatePHI(WTy, Phi->getNumIncomingValues());
            for (unsigned i = 0; i < Phi->getNumIncomingValues(); ++i)
            {
                IRBuilder<> BPhi(Phi->getIncomingBlock(i)->getTerminator());
                Value *In = rebuildNarrow(Phi->getIncomingValue(i), WT, BPhi, C);
                if (!In)
                    return nullptr;
                NewPhi->addIncoming(In, Phi->getIncomingBlock(i));
            }
            return NewPhi;
        }

        // Fallback: safe truncation when we know only low WT bits are demanded at all uses.
        return B.CreateTrunc(V, WTy);
    }

    // Force V to exactly WTy using trunc/zext; rebuild constants at WTy.
    static Value *ensureWidth(Value *V, Type *WTy, IRBuilder<> &B)
    {
        if (!V->getType()->isIntegerTy() || V->getType() == WTy)
            return V;
        unsigned SrcW = cast<IntegerType>(V->getType())->getBitWidth();
        unsigned DstW = cast<IntegerType>(WTy)->getBitWidth();
        if (auto *CI = dyn_cast<ConstantInt>(V))
        {
            APInt AP = CI->getValue();
            AP = (SrcW >= DstW) ? AP.trunc(DstW) : AP.zext(DstW);
            return ConstantInt::get(WTy, AP);
        }
        // Low-bit semantics: zext for narrower, trunc for wider.
        return (SrcW > DstW) ? B.CreateTrunc(V, WTy) : B.CreateZExt(V, WTy);
    }

    // Make a shift amount constant match WTy.
    static Constant *constShiftOfWidth(ConstantInt *C, Type *WTy)
    {
        unsigned DstW = cast<IntegerType>(WTy)->getBitWidth();
        return ConstantInt::get(WTy, C->getValue().zextOrTrunc(DstW));
    }

    static Value *narrowBinOp(BinaryOperator *BO, unsigned WT, IRBuilder<> &B, const Ctx &C)
    {
        Type *WTy = IntegerType::get(B.getContext(), WT);
        auto Op = BO->getOpcode();

        // Rebuild operands (may be null if not supported).
        Value *L = rebuildNarrow(BO->getOperand(0), WT, B, C);
        Value *R = rebuildNarrow(BO->getOperand(1), WT, B, C);
        if (!L)
            L = BO->getOperand(0);
        if (!R)
            R = BO->getOperand(1);

        // Force exact type match for both operands.
        L = ensureWidth(L, WTy, B);
        R = ensureWidth(R, WTy, B);

        // Bitwise/arith ops: compute at WTy.
        if (Op == Instruction::And || Op == Instruction::Or || Op == Instruction::Xor ||
            Op == Instruction::Add || Op == Instruction::Sub || Op == Instruction::Mul)
        {
            auto New = B.CreateBinOp((Instruction::BinaryOps)Op, L, R);

            outs() << "    Rebuilt binop: " << *BO << " --> " << *New << "\n";
        }

        // Shifts by constant: RHS must be ConstantInt of WTy.
        if (Op == Instruction::Shl || Op == Instruction::LShr || Op == Instruction::AShr)
        {
            if (auto *RC = dyn_cast<ConstantInt>(R))
            {
                R = constShiftOfWidth(RC, WTy);
                auto New = B.CreateBinOp((Instruction::BinaryOps)Op, L, R);

                outs() << "    Rebuilt shift: " << *BO << " --> " << *New << "\n";

                return New;
            }
            // Variable shift: bail (keep wide) or add stricter WT checks elsewhere.
            return nullptr;
        }

        return nullptr;
    }

public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM)
    {
        const DataLayout &DL = F.getParent()->getDataLayout();
        auto &AC = AM.getResult<AssumptionAnalysis>(F);
        auto &DT = AM.getResult<DominatorTreeAnalysis>(F);
        auto &DB = AM.getResult<DemandedBitsAnalysis>(F);
        Ctx C{DL, AC, DT, DB};

        SmallVector<Instruction *, 128> Work;
        for (auto &BB : F)
            for (auto &I : BB)
                if (I.getType()->isIntegerTy())
                    Work.push_back(&I);

        bool Changed = false;
        for (Instruction *I : Work)
        {
            if (!I || !I->getType()->isIntegerTy())
                continue;
            unsigned BW = cast<IntegerType>(I->getType())->getBitWidth();

            APInt Demanted = C.DB.getDemandedBits(I);
            unsigned N = 0;
            if (!isContiguousLowMask(Demanted, N))
                continue;

            unsigned WT = chooseTargetWidth(N, /*RoundToByte=*/true);
            if (WT >= BW)
                continue;

            // Ensure each use only demands low WT bits.
            APInt LowWT = APInt::getLowBitsSet(BW, WT);
            bool AllUsesOK = true;
            for (Use &U : I->uses())
            {
                APInt UD = C.DB.getDemandedBits(&U);
                if (!UD.isSubsetOf(LowWT))
                {
                    AllUsesOK = false;
                    break;
                }
            }
            if (!AllUsesOK)
                continue;

            outs() << "WidthNormalizePass: Narrowing " << *I
                   << " from " << BW << " to " << WT << " bits.\n";

            IRBuilder<> B(I);
            if (Value *NVal = rebuildNarrow(I, WT, B, C))
            {
                outs() << "    Rebuilt value: " << *NVal << "\n";

                Value *Z = B.CreateZExt(NVal, I->getType());
                // Replace uses; optionally, delete redundant final and-masks.
                SmallVector<Use *, 16> Uses;
                for (Use &U : I->uses())
                    Uses.push_back(&U);
                for (Use *U : Uses)
                {
                    U->set(Z);
                }
                Changed = true;
            }
        }

        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};