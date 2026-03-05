
#include "constant_memory_folding_pass.hpp"

#include "../pass_utils.hpp"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Constants.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/Operator.h>
#include <llvm/Support/raw_ostream.h>

#include "compat/lief_compat.hpp"

// Debug logging for constant memory folding
#define CMFP_DEBUG 0

#if CMFP_DEBUG
#define CMFP_LOG(x) llvm::errs() << "[CMFP] " << x << "\n"
#else
#define CMFP_LOG(x)
#endif

using namespace llvm;
using namespace lifted;

std::optional<uint64_t> ConstantMemoryFoldingPass::tryGetConstantAddress(GEPOperator *GEP, Module *M) const
{
    // Extract constant offset
    APInt Offset(64, 0);
    if (GEP->accumulateConstantOffset(M->getDataLayout(), Offset))
    {
        uint64_t addr = Offset.getZExtValue();

        // Check if address is in a constant range
        // TODO: optimize with interval tree
        for (const auto &range : ConstMemoryRvaRanges)
        {
            if (range.contains(addr))
            {
                return addr;
            }
        }
    }

    return std::nullopt;
}

std::optional<ConstantMemoryFoldingPass::SelectInfo> ConstantMemoryFoldingPass::tryGetConstantAddressSelect(GEPOperator *GEP) const
{
    if (auto *SI = dyn_cast<SelectInst>(GEP->getOperand(2))) // TODO: what if it's the second one? what if its not [0, %select]?
    {
        auto *TrueVal = dyn_cast<ConstantInt>(SI->getTrueValue());
        auto *FalseVal = dyn_cast<ConstantInt>(SI->getFalseValue());
        if (!TrueVal || !FalseVal)
        {
            return std::nullopt;
        }

        uint64_t TrueRVA = TrueVal->getZExtValue();
        uint64_t FalseRVA = FalseVal->getZExtValue();

        bool TrueInRange = false;
        bool FalseInRange = false;

        for (const auto &range : ConstMemoryRvaRanges)
        {
            if (range.contains(TrueRVA))
            {
                TrueInRange = true;
            }
            if (range.contains(FalseRVA))
            {
                FalseInRange = true;
            }
        }

        if (TrueInRange && FalseInRange)
        {
            return SelectInfo{SI, GEP, TrueRVA, FalseRVA};
        }
    }
    return std::nullopt;
}

std::optional<ConstantMemoryFoldingPass::SelectBasedIndexInfo>
ConstantMemoryFoldingPass::analyzeSelectBasedIndex(GEPOperator *GEP, Module *M) const
{
    CMFP_LOG("Analyzing GEP for select-based index");

    // Get the index operand (for [0 x i8], ptr @RAM, i64 0, i64 %idx, it's operand 2)
    if (GEP->getNumOperands() < 3)
    {
        return std::nullopt;
    }

    Value *IndexVal = GEP->getOperand(2);
    CMFP_LOG("  Index value: " << *IndexVal);

    // Trace back through the def-use chain to find a select with constant alternatives
    SmallVector<Instruction *, 8> Chain;
    Value *Current = IndexVal;
    SelectInst *RootSelect = nullptr;

    // Walk backwards through the instruction chain
    while (auto *Inst = dyn_cast<Instruction>(Current))
    {
        CMFP_LOG("  Tracing: " << *Inst);

        if (auto *SI = dyn_cast<SelectInst>(Inst))
        {
            // Found a select - check if both alternatives are constants
            auto *TrueConst = dyn_cast<ConstantInt>(SI->getTrueValue());
            auto *FalseConst = dyn_cast<ConstantInt>(SI->getFalseValue());

            if (TrueConst && FalseConst)
            {
                CMFP_LOG("  Found root select with constant alternatives: "
                         << TrueConst->getZExtValue() << " and " << FalseConst->getZExtValue());
                RootSelect = SI;
                break;
            }
            else
            {
                CMFP_LOG("  Select found but alternatives not both constant");
                return std::nullopt;
            }
        }

        // Only follow through "constant-foldable" operations
        // These are operations that can be folded when operands are constant
        if (!isa<BinaryOperator>(Inst) && !isa<CastInst>(Inst) && !isa<SelectInst>(Inst))
        {
            CMFP_LOG("  Non-foldable instruction type encountered");
            return std::nullopt;
        }

        Chain.push_back(Inst);

        // For binary operators and casts, we need exactly one operand to continue
        // (the other should be constant or we can't fold)
        if (auto *BinOp = dyn_cast<BinaryOperator>(Inst))
        {
            Value *Op0 = BinOp->getOperand(0);
            Value *Op1 = BinOp->getOperand(1);

            bool Op0IsConst = isa<Constant>(Op0);
            bool Op1IsConst = isa<Constant>(Op1);

            if (Op0IsConst && Op1IsConst)
            {
                CMFP_LOG("  Both operands constant - should have been folded already");
                return std::nullopt;
            }
            else if (Op0IsConst)
            {
                Current = Op1;
            }
            else if (Op1IsConst)
            {
                Current = Op0;
            }
            else
            {
                CMFP_LOG("  Binary op has no constant operands");
                return std::nullopt;
            }
        }
        else if (auto *Cast = dyn_cast<CastInst>(Inst))
        {
            Current = Cast->getOperand(0);
        }
        else
        {
            CMFP_LOG("  Unexpected instruction in chain");
            return std::nullopt;
        }
    }

    if (!RootSelect)
    {
        CMFP_LOG("  No root select found");
        return std::nullopt;
    }

    // Now we need to symbolically evaluate the chain for both select alternatives
    // to get the final RVA values
    auto *TrueConst = cast<ConstantInt>(RootSelect->getTrueValue());
    auto *FalseConst = cast<ConstantInt>(RootSelect->getFalseValue());

    // Clone the chain and replace select with each constant, then fold
    auto FoldChain = [&](Constant *SelectReplacement) -> std::optional<uint64_t>
    {
        SmallDenseMap<Value *, Constant *> ConstMap;
        ConstMap[RootSelect] = SelectReplacement;

        // Walk forward through the chain, folding each instruction
        for (auto it = Chain.rbegin(); it != Chain.rend(); ++it)
        {
            Instruction *Inst = *it;

            SmallVector<Constant *, 4> Operands;
            for (Use &U : Inst->operands())
            {
                Value *Op = U.get();
                if (auto *C = dyn_cast<Constant>(Op))
                {
                    Operands.push_back(C);
                }
                else if (auto It = ConstMap.find(Op); It != ConstMap.end())
                {
                    Operands.push_back(It->second);
                }
                else
                {
                    CMFP_LOG("    Cannot fold - operand not constant: " << *Op);
                    return std::nullopt;
                }
            }

            // Try to fold the instruction
            Constant *Folded = nullptr;
            if (auto *BinOp = dyn_cast<BinaryOperator>(Inst))
            {
                Folded = ConstantExpr::get(BinOp->getOpcode(), Operands[0], Operands[1]);
            }
            else if (auto *Cast = dyn_cast<CastInst>(Inst))
            {
                Folded = ConstantExpr::getCast(Cast->getOpcode(), Operands[0], Cast->getType());
            }
            else if (auto *Sel = dyn_cast<SelectInst>(Inst))
            {
                if (auto *Cond = dyn_cast<Constant>(Sel->getCondition()))
                {
                    Folded = ConstantExpr::getSelect(Cond, Operands[0], Operands[1]);
                }
            }

            if (!Folded)
            {
                CMFP_LOG("    Cannot create constant expression for: " << *Inst);
                return std::nullopt;
            }

            // Simplify the constant expression
            if (auto *SimplifiedC = ConstantFoldConstant(Folded, M->getDataLayout()))
            {
                Folded = SimplifiedC;
            }

            ConstMap[Inst] = Folded;
        }

        // The last instruction in the chain should now be fully folded
        Constant *FinalConst = ConstMap[Chain.front()];
        if (auto *CI = dyn_cast<ConstantInt>(FinalConst))
        {
            return CI->getZExtValue();
        }

        CMFP_LOG("    Final value not a constant int");
        return std::nullopt;
    };

    auto TrueRVA = FoldChain(TrueConst);
    auto FalseRVA = FoldChain(FalseConst);

    if (!TrueRVA || !FalseRVA)
    {
        CMFP_LOG("  Failed to fold one or both paths");
        return std::nullopt;
    }

    CMFP_LOG("  Successfully folded: True=" << *TrueRVA << ", False=" << *FalseRVA);

    // Check if both RVAs are in constant memory ranges
    bool TrueInRange = false;
    bool FalseInRange = false;

    for (const auto &range : ConstMemoryRvaRanges)
    {
        if (range.contains(*TrueRVA))
        {
            TrueInRange = true;
        }
        if (range.contains(*FalseRVA))
        {
            FalseInRange = true;
        }
    }

    if (!TrueInRange || !FalseInRange)
    {
        CMFP_LOG("  One or both RVAs not in constant memory range");
        return std::nullopt;
    }

    CMFP_LOG("  Both RVAs in constant memory - optimization applicable");

    return SelectBasedIndexInfo{RootSelect, GEP, Chain, *TrueRVA, *FalseRVA};
}

Constant *ConstantMemoryFoldingPass::extractConstantFromRVA(uint64_t RVA, Type *Ty)
{
    unsigned NumBits = Ty->getPrimitiveSizeInBits(); // TODO: What if not multiple of 8?
    unsigned NumBytes = NumBits / 8;

    // Read constant bytes from your binary data
    const uint8_t *RVAData = Binary.get_content_from_virtual_address(RVA, NumBytes).data();

    APInt Value(NumBits, 0);
    for (unsigned i = 0; i < NumBytes; ++i)
    {
        Value |= APInt(NumBits, RVAData[i]) << (i * 8);
    }

    if (Ty->isIntegerTy())
    {
        return ConstantInt::get(Ty, Value);
    }
    else if (Ty->isFloatTy() || Ty->isDoubleTy())
    {
        return ConstantFP::get(Ty->getContext(),
                               APFloat(Ty->getFltSemantics(), Value));
    }
    else if (Ty->isPointerTy())
    {
        return ConstantExpr::getIntToPtr(
            ConstantInt::get(Type::getInt64Ty(Ty->getContext()), Value.getZExtValue()),
            Ty);
    }

    return nullptr;
}

bool ConstantMemoryFoldingPass::replaceLoadWithConstant(LoadInst *LI, uint64_t RVA)
{
    Type *LoadTy = LI->getType();

    Constant *ConstVal = extractConstantFromRVA(RVA, LoadTy);
    if (!ConstVal)
    {
        return false;
    }

    // Replace all uses of the load with the constant
    LI->replaceAllUsesWith(ConstVal);
    LI->eraseFromParent();

    return true;
}

bool ConstantMemoryFoldingPass::replaceLoadWithConstantSelect(LoadInst *LI, const SelectInfo &SInfo)
{
    Type *LoadTy = LI->getType();

    // We can only handle integer types for now
    if (!LoadTy->isIntegerTy())
    {
        return false;
    }

    Constant *ConstTrue = extractConstantFromRVA(SInfo.TrueRVA, LoadTy);
    Constant *ConstFalse = extractConstantFromRVA(SInfo.FalseRVA, LoadTy);
    if (!ConstTrue || !ConstFalse)
    {
        return false;
    }

    // Create new select instruction with constants
    SelectInst *NewSI = SelectInst::Create(
        SInfo.SI->getCondition(),
        ConstTrue,
        ConstFalse,
        SInfo.SI->getName(),
        SInfo.SI);

    // Replace all uses of the load with the new select
    LI->replaceAllUsesWith(NewSI);
    LI->eraseFromParent();
    if (auto *GEPI = dyn_cast<GetElementPtrInst>(SInfo.GEP))
    {
        // If the GEP has no other uses, we can remove it
        if (GEPI->use_empty())
        {
            GEPI->eraseFromParent();
        }
    }
    SInfo.SI->eraseFromParent();

    return true;
}

bool ConstantMemoryFoldingPass::replaceLoadWithSelectHoist(LoadInst *LI, const SelectBasedIndexInfo &Info)
{
    Type *LoadTy = LI->getType();

    CMFP_LOG("Replacing load with hoisted select");
    CMFP_LOG("  Load type: " << *LoadTy);

    // Extract constants from both RVAs
    Constant *ConstTrue = extractConstantFromRVA(Info.TrueRVA, LoadTy);
    Constant *ConstFalse = extractConstantFromRVA(Info.FalseRVA, LoadTy);

    if (!ConstTrue || !ConstFalse)
    {
        CMFP_LOG("  Failed to extract constants from RVAs");
        return false;
    }

    CMFP_LOG("  True constant: " << *ConstTrue);
    CMFP_LOG("  False constant: " << *ConstFalse);

    // Create new select instruction with the constant values
    // Insert it where the root select was, so it's in the right place
    SelectInst *NewSelect = SelectInst::Create(
        Info.RootSelect->getCondition(),
        ConstTrue,
        ConstFalse,
        "const.select",
        Info.RootSelect);

    CMFP_LOG("  Created new select: " << *NewSelect);

    // Replace all uses of the load with the new select
    LI->replaceAllUsesWith(NewSelect);
    LI->eraseFromParent();

    CMFP_LOG("  Replaced load and erased it");

    // Clean up dead instructions in the chain if they have no other uses
    for (auto *Inst : Info.IndexChain)
    {
        if (Inst->use_empty())
        {
            CMFP_LOG("  Erasing dead instruction: " << *Inst);
            Inst->eraseFromParent();
        }
    }

    // Clean up the GEP if it's now dead
    if (auto *GEPI = dyn_cast<GetElementPtrInst>(Info.GEP))
    {
        if (GEPI->use_empty())
        {
            CMFP_LOG("  Erasing dead GEP");
            GEPI->eraseFromParent();
        }
    }

    // Clean up the root select if it's now dead
    if (Info.RootSelect->use_empty())
    {
        CMFP_LOG("  Erasing dead root select");
        Info.RootSelect->eraseFromParent();
    }

    return true;
}

PreservedAnalyses ConstantMemoryFoldingPass::run(Function &F, FunctionAnalysisManager &)
{
    bool Changed = false;

    CMFP_LOG("Running ConstantMemoryFoldingPass on function: " << F.getName());

    std::vector<std::pair<LoadInst *, uint64_t>> toReplaceLI;
    std::vector<std::pair<LoadInst *, SelectInfo>> toReplaceSI;
    std::vector<std::pair<LoadInst *, SelectBasedIndexInfo>> toReplaceSelectBased;

    for (BasicBlock &BB : F)
    {
        for (Instruction &I : BB)
        {
            if (auto *LI = dyn_cast<LoadInst>(&I))
            {
                if (auto *GEP = passes::isRAMGEP(LI->getPointerOperand()))
                {
                    CMFP_LOG("Found RAM load: " << *LI);

                    if (auto RVA = tryGetConstantAddress(GEP, F.getParent()))
                    {
                        CMFP_LOG("  Constant address: " << *RVA);
                        toReplaceLI.push_back({LI, *RVA});
                    }
                    else if (auto SInfo = tryGetConstantAddressSelect(GEP))
                    {
                        CMFP_LOG("  Direct select in GEP");
                        toReplaceSI.push_back({LI, *SInfo});
                    }
                    else if (auto SelectInfo = analyzeSelectBasedIndex(GEP, F.getParent()))
                    {
                        CMFP_LOG("  Select-based index detected");
                        toReplaceSelectBased.push_back({LI, *SelectInfo});
                    }
                    else
                    {
                        CMFP_LOG("  No optimization applicable");
                    }
                }
            }
        }
    }

    CMFP_LOG("Found " << toReplaceLI.size() << " constant loads");
    CMFP_LOG("Found " << toReplaceSI.size() << " direct select loads");
    CMFP_LOG("Found " << toReplaceSelectBased.size() << " select-based index loads");

    for (const auto &[LI, RVA] : toReplaceLI)
    {
        Changed |= replaceLoadWithConstant(LI, RVA);
    }
    for (const auto &[LI, SInfo] : toReplaceSI)
    {
        Changed |= replaceLoadWithConstantSelect(LI, SInfo);
    }
    for (const auto &[LI, Info] : toReplaceSelectBased)
    {
        Changed |= replaceLoadWithSelectHoist(LI, Info);
    }

    CMFP_LOG("Pass " << (Changed ? "modified" : "did not modify") << " function\n");

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
