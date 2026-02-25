#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/Analysis/DemandedBits.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"

class WidthNormalizePass : public llvm::PassInfoMixin<WidthNormalizePass>
{
    struct Ctx
    {
        const llvm::DataLayout &DL;
        llvm::AssumptionCache &AC;
        llvm::DominatorTree &DT;
        llvm::DemandedBits &DB;
    };

    static bool isContiguousLowMask(const llvm::APInt &M, unsigned &N)
    {
        if (M.isZero())
            return false;
        N = M.countTrailingOnes();
        return M == llvm::APInt::getLowBitsSet(M.getBitWidth(), N);
    }

    static unsigned chooseTargetWidth(unsigned N, bool RoundToByte = true)
    {
        if (!RoundToByte)
            return std::max(1u, N);
        return std::max(8u, (N + 7) & ~7u);
    }

    static llvm::Value *rebuildNarrow(llvm::Value *V, unsigned WT, llvm::IRBuilder<> &B, const Ctx &C)
    {
        if (V->getType()->isIntegerTy(WT))
            return V;
        if (!V->getType()->isIntegerTy())
            return nullptr;

        llvm::Type *WTy = llvm::IntegerType::get(B.getContext(), WT);

        if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(V))
        {
            llvm::IRBuilder<> BI(LI);

            llvm::Value *Ptr = LI->getPointerOperand();

            llvm::LoadInst *NewL = BI.CreateLoad(WTy, Ptr);
            NewL->setAlignment(LI->getAlign());
            NewL->setVolatile(LI->isVolatile());
            return NewL;
        }

        if (auto *ZI = llvm::dyn_cast<llvm::ZExtInst>(V))
        {
            llvm::Value *S = ZI->getOperand(0);
            if (auto *STy = llvm::dyn_cast<llvm::IntegerType>(S->getType()))
            {
                if (STy->getBitWidth() <= WT)
                {
                    llvm::Value *Sn = rebuildNarrow(S, STy->getBitWidth(), B, C);
                    return STy->getBitWidth() == WT ? Sn : B.CreateZExt(Sn, WTy);
                }
            }
        }

        if (auto *TI = llvm::dyn_cast<llvm::TruncInst>(V))
        {
            llvm::Value *S = TI->getOperand(0);
            unsigned SW = llvm::cast<llvm::IntegerType>(S->getType())->getBitWidth();
            if (WT <= TI->getType()->getIntegerBitWidth())
                return B.CreateTrunc(rebuildNarrow(S, std::min<unsigned>(SW, WT), B, C), WTy);
            // If WT > trunc target, we still can rebuild producer in WT and drop the old trunc at users.
            return B.CreateTrunc(rebuildNarrow(S, std::min<unsigned>(SW, WT), B, C), WTy);
        }

        if (auto *BO = llvm::dyn_cast<llvm::BinaryOperator>(V))
        {
            if (llvm::Value *R = narrowBinOp(BO, WT, B, C))
                return R;
        }

        if (auto *Sel = llvm::dyn_cast<llvm::SelectInst>(V))
        {
            llvm::Value *T = rebuildNarrow(Sel->getTrueValue(), WT, B, C);
            llvm::Value *F = rebuildNarrow(Sel->getFalseValue(), WT, B, C);
            if (!T || !F)
                return nullptr;
            return B.CreateSelect(Sel->getCondition(), T, F);
        }

        if (auto *Phi = llvm::dyn_cast<llvm::PHINode>(V))
        {
            llvm::PHINode *NewPhi = B.CreatePHI(WTy, Phi->getNumIncomingValues());
            for (unsigned i = 0; i < Phi->getNumIncomingValues(); ++i)
            {
                llvm::IRBuilder<> BPhi(Phi->getIncomingBlock(i)->getTerminator());
                llvm::Value *In = rebuildNarrow(Phi->getIncomingValue(i), WT, BPhi, C);
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
    static llvm::Value *ensureWidth(llvm::Value *V, llvm::Type *WTy, llvm::IRBuilder<> &B)
    {
        if (!V->getType()->isIntegerTy() || V->getType() == WTy)
            return V;
        unsigned SrcW = llvm::cast<llvm::IntegerType>(V->getType())->getBitWidth();
        unsigned DstW = llvm::cast<llvm::IntegerType>(WTy)->getBitWidth();
        if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(V))
        {
            llvm::APInt AP = CI->getValue();
            AP = (SrcW >= DstW) ? AP.trunc(DstW) : AP.zext(DstW);
            return llvm::ConstantInt::get(WTy, AP);
        }
        // Low-bit semantics: zext for narrower, trunc for wider.
        return (SrcW > DstW) ? B.CreateTrunc(V, WTy) : B.CreateZExt(V, WTy);
    }

    // Make a shift amount constant match WTy.
    static llvm::Constant *constShiftOfWidth(llvm::ConstantInt *C, llvm::Type *WTy)
    {
        unsigned DstW = llvm::cast<llvm::IntegerType>(WTy)->getBitWidth();
        return llvm::ConstantInt::get(WTy, C->getValue().zextOrTrunc(DstW));
    }

    static llvm::Value *narrowBinOp(llvm::BinaryOperator *BO, unsigned WT, llvm::IRBuilder<> &B, const Ctx &C)
    {
        llvm::Type *WTy = llvm::IntegerType::get(B.getContext(), WT);
        auto Op = BO->getOpcode();

        // Rebuild operands (may be null if not supported).
        llvm::Value *L = rebuildNarrow(BO->getOperand(0), WT, B, C);
        llvm::Value *R = rebuildNarrow(BO->getOperand(1), WT, B, C);
        if (!L)
            L = BO->getOperand(0);
        if (!R)
            R = BO->getOperand(1);

        // Force exact type match for both operands.
        L = ensureWidth(L, WTy, B);
        R = ensureWidth(R, WTy, B);

        // Bitwise/arith ops: compute at WTy.
        if (Op == llvm::Instruction::And || Op == llvm::Instruction::Or || Op == llvm::Instruction::Xor ||
            Op == llvm::Instruction::Add || Op == llvm::Instruction::Sub || Op == llvm::Instruction::Mul)
        {
            auto New = B.CreateBinOp((llvm::Instruction::BinaryOps)Op, L, R);

            llvm::outs() << "    Rebuilt binop: " << *BO << " --> " << *New << "\n";
        }

        // Shifts by constant: RHS must be ConstantInt of WTy.
        if (Op == llvm::Instruction::Shl || Op == llvm::Instruction::LShr || Op == llvm::Instruction::AShr)
        {
            if (auto *RC = llvm::dyn_cast<llvm::ConstantInt>(R))
            {
                R = constShiftOfWidth(RC, WTy);
                auto New = B.CreateBinOp((llvm::Instruction::BinaryOps)Op, L, R);

                llvm::outs() << "    Rebuilt shift: " << *BO << " --> " << *New << "\n";

                return New;
            }
            // Variable shift: bail (keep wide) or add stricter WT checks elsewhere.
            return nullptr;
        }

        return nullptr;
    }

public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM)
    {
        const llvm::DataLayout &DL = F.getParent()->getDataLayout();
        auto &AC = AM.getResult<llvm::AssumptionAnalysis>(F);
        auto &DT = AM.getResult<llvm::DominatorTreeAnalysis>(F);
        auto &DB = AM.getResult<llvm::DemandedBitsAnalysis>(F);
        Ctx C{DL, AC, DT, DB};

        llvm::SmallVector<llvm::Instruction *, 128> Work;
        for (auto &BB : F)
            for (auto &I : BB)
                if (I.getType()->isIntegerTy())
                    Work.push_back(&I);

        bool Changed = false;
        for (llvm::Instruction *I : Work)
        {
            if (!I || !I->getType()->isIntegerTy())
                continue;
            unsigned BW = llvm::cast<llvm::IntegerType>(I->getType())->getBitWidth();

            llvm::APInt Demanted = C.DB.getDemandedBits(I);
            unsigned N = 0;
            if (!isContiguousLowMask(Demanted, N))
                continue;

            unsigned WT = chooseTargetWidth(N, /*RoundToByte=*/true);
            if (WT >= BW)
                continue;

            // Ensure each use only demands low WT bits.
            llvm::APInt LowWT = llvm::APInt::getLowBitsSet(BW, WT);
            bool AllUsesOK = true;
            for (llvm::Use &U : I->uses())
            {
                llvm::APInt UD = C.DB.getDemandedBits(&U);
                if (!UD.isSubsetOf(LowWT))
                {
                    AllUsesOK = false;
                    break;
                }
            }
            if (!AllUsesOK)
                continue;

            llvm::outs() << "WidthNormalizePass: Narrowing " << *I
                         << " from " << BW << " to " << WT << " bits.\n";

            llvm::IRBuilder<> B(I);
            if (llvm::Value *NVal = rebuildNarrow(I, WT, B, C))
            {
                llvm::outs() << "    Rebuilt value: " << *NVal << "\n";

                llvm::Value *Z = B.CreateZExt(NVal, I->getType());
                // Replace uses; optionally, delete redundant final and-masks.
                llvm::SmallVector<llvm::Use *, 16> Uses;
                for (llvm::Use &U : I->uses())
                    Uses.push_back(&U);
                for (llvm::Use *U : Uses)
                {
                    U->set(Z);
                }
                Changed = true;
            }
        }

        return Changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
    }
};