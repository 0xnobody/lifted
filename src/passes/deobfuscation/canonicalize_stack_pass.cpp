// CanonicalizeStackPass.cpp
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/Local.h"

#include "canonicalize_stack_pass.hpp"

using namespace llvm;
using namespace llvm::PatternMatch;

struct Site
{
    GetElementPtrInst *GEP = nullptr; // GEP into @RAM
    Instruction *MemI = nullptr;      // load/store/atomic using the GEP
    Value *Idx = nullptr;             // original index (byte offset)
    uint64_t AccessBytes = 1;         // width of memory access in bytes
    // Decomposition: Idx = RSP + Rem
    bool HasRsp = false;
    Value *Rem = nullptr; // may be non-constant, i64-typed

    void debug_print()
    {
        outs() << "Site:\n";
        outs() << "  GEP: " << *GEP << "\n";
        outs() << "  MemI: " << *MemI << "\n";
        outs() << "  Idx: " << *Idx << "\n";
        outs() << "  AccessBytes: " << AccessBytes << "\n";
        outs() << "  HasRsp: " << (HasRsp ? "true" : "false") << "\n";
        if (Rem)
            outs() << "  Rem: " << *Rem << "\n";
    }
};

// Utilities

static int64_t alignDown64(int64_t v, uint64_t a)
{
    int64_t m = (int64_t)a;
    return (v / m) * m;
}
static int64_t alignTo64(int64_t v, uint64_t a)
{
    int64_t m = (int64_t)a;
    int64_t r = v % m;
    return r == 0 ? v : v + (m - r);
}

static GlobalVariable *findRAMGlobal(Module &M)
{
    // Preferred: a global named "RAM".
    if (GlobalVariable *G = M.getGlobalVariable("RAM"))
        return G;
    // Fallback: any global used as base of GEPs with element [0 x i8].
    for (GlobalVariable &G : M.globals())
    {
        for (User *U : G.users())
        {
            if (auto *GEP = dyn_cast<GetElementPtrInst>(U))
            {
                if (auto *AT = dyn_cast<ArrayType>(GEP->getSourceElementType()))
                {
                    if (AT->getElementType()->isIntegerTy(8))
                        return &G;
                }
            }
        }
    }
    return nullptr;
}

Argument *getRspArgument(Function &F)
{
    // Use position 4 if available, otherwise try by name.
    if (F.arg_size() >= 5)
    {
        auto It = F.arg_begin();
        std::advance(It, 4);
        return &*It;
    }
    for (Argument &A : F.args())
    {
        if (A.getName().equals_insensitive("rsp"))
            return &A;
    }
    return nullptr;
}

bool isRAMGEP(GetElementPtrInst *GEP, GlobalVariable &RAM)
{
    Value *Base = GEP->getPointerOperand();
    if (Base == &RAM)
        return true;
    if (auto *BC = dyn_cast<BitCastInst>(Base))
        return BC->getOperand(0) == &RAM;
    return false;
}

// Helper: strip pointer casts.
static Value *stripCasts(Value *V)
{
    return V->stripPointerCasts();
}

// Helper: try to fold a constant trailing GEP offset into an i64 Value.
static bool foldConstGEP(GetElementPtrInst *GEP, APInt &ByteDelta)
{
    // Only support linear i8 addressing or trailing linear index.
    if (auto *AT = dyn_cast<ArrayType>(GEP->getSourceElementType()))
    {
        if (!AT->getElementType()->isIntegerTy(8))
            return false;
    }
    Value *Idx = GEP->getOperand(GEP->getNumOperands() - 1);
    if (auto *C = dyn_cast<ConstantInt>(Idx))
    {
        ByteDelta += C->getValue().sext(64);
        return true;
    }
    return false;
}

// NEW: recursively collect memory users through casts and constant-index GEPs.
static void collectMemUsersTransitively(GetElementPtrInst *RootGEP,
                                        GlobalVariable &RAM,
                                        const DataLayout &DL,
                                        SmallVectorImpl<Site> &Out)
{
    SmallVector<std::pair<Value *, APInt>, 16> Work;
    Work.emplace_back(RootGEP, APInt(64, 0, /*signed*/ true));
    while (!Work.empty())
    {
        auto [V, Delta] = Work.pop_back_val();

        for (User *U : V->users())
        {
            if (auto *LI = dyn_cast<LoadInst>(U))
            {
                Site S;
                S.GEP = RootGEP;
                S.MemI = LI;
                S.Idx = nullptr;
                S.AccessBytes =
                    DL.getTypeStoreSize(LI->getType()).getFixedValue();
                // Compute final index by adding Delta to the original index.
                Value *BaseIdx = RootGEP->getOperand(RootGEP->getNumOperands() - 1);
                IRBuilder<> B(RootGEP);
                Value *Idx64 = BaseIdx;
                if (!isa<ConstantInt>(Idx64) || !Idx64->getType()->isIntegerTy(64))
                    Idx64 = B.CreateSExtOrTrunc(BaseIdx, Type::getInt64Ty(RootGEP->getContext()));
                Value *DeltaV = ConstantInt::get(Type::getInt64Ty(RootGEP->getContext()),
                                                 Delta.sext(64));
                S.Idx = B.CreateAdd(Idx64, DeltaV, "idx.delta");
                Out.push_back(S);
            }
            else if (auto *SI = dyn_cast<StoreInst>(U))
            {
                Site S;
                S.GEP = RootGEP;
                S.MemI = SI;
                S.Idx = nullptr;
                S.AccessBytes =
                    DL.getTypeStoreSize(SI->getValueOperand()->getType()).getFixedValue();
                IRBuilder<> B(RootGEP);
                Value *BaseIdx = RootGEP->getOperand(RootGEP->getNumOperands() - 1);
                Value *Idx64 = BaseIdx;
                if (!isa<ConstantInt>(Idx64) || !Idx64->getType()->isIntegerTy(64))
                    Idx64 = B.CreateSExtOrTrunc(BaseIdx, Type::getInt64Ty(RootGEP->getContext()));
                Value *DeltaV = ConstantInt::get(Type::getInt64Ty(RootGEP->getContext()),
                                                 Delta.sext(64));
                S.Idx = B.CreateAdd(Idx64, DeltaV, "idx.delta");
                Out.push_back(S);
            }
            else if (auto *RMW = dyn_cast<AtomicRMWInst>(U))
            {
                Site S;
                S.GEP = RootGEP;
                S.MemI = RMW;
                S.Idx = nullptr;
                S.AccessBytes =
                    DL.getTypeStoreSize(RMW->getValOperand()->getType()).getFixedValue();
                IRBuilder<> B(RootGEP);
                Value *BaseIdx = RootGEP->getOperand(RootGEP->getNumOperands() - 1);
                Value *Idx64 = BaseIdx;
                if (!isa<ConstantInt>(Idx64) || !Idx64->getType()->isIntegerTy(64))
                    Idx64 = B.CreateSExtOrTrunc(BaseIdx, Type::getInt64Ty(RootGEP->getContext()));
                Value *DeltaV = ConstantInt::get(Type::getInt64Ty(RootGEP->getContext()),
                                                 Delta.sext(64));
                S.Idx = B.CreateAdd(Idx64, DeltaV, "idx.delta");
                Out.push_back(S);
            }
            else if (auto *CX = dyn_cast<AtomicCmpXchgInst>(U))
            {
                Site S;
                S.GEP = RootGEP;
                S.MemI = CX;
                S.Idx = nullptr;
                S.AccessBytes =
                    DL.getTypeStoreSize(CX->getNewValOperand()->getType()).getFixedValue();
                IRBuilder<> B(RootGEP);
                Value *BaseIdx = RootGEP->getOperand(RootGEP->getNumOperands() - 1);
                Value *Idx64 = BaseIdx;
                if (!isa<ConstantInt>(Idx64) || !Idx64->getType()->isIntegerTy(64))
                    Idx64 = B.CreateSExtOrTrunc(BaseIdx, Type::getInt64Ty(RootGEP->getContext()));
                Value *DeltaV = ConstantInt::get(Type::getInt64Ty(RootGEP->getContext()),
                                                 Delta.sext(64));
                S.Idx = B.CreateAdd(Idx64, DeltaV, "idx.delta");
                Out.push_back(S);
            }
            else if (auto *BC = dyn_cast<BitCastInst>(U))
            {
                Work.emplace_back(BC, Delta);
            }
            else if (auto *ASC = dyn_cast<AddrSpaceCastInst>(U))
            {
                Work.emplace_back(ASC, Delta);
            }
            else if (auto *G2 = dyn_cast<GetElementPtrInst>(U))
            {
                APInt NewDelta = Delta;
                if (foldConstGEP(G2, NewDelta))
                {
                    Work.emplace_back(G2, NewDelta);
                } // else ignore non-constant extra indexing here (handled elsewhere).
            }
        }
    }
}

bool collectSites(Function &F, GlobalVariable &RAM, Argument &RspArg,
                  const DataLayout &DL, SmallVectorImpl<Site> &Out)
{
    for (BasicBlock &BB : F)
    {
        for (Instruction &I : BB)
        {
            auto *GEP = dyn_cast<GetElementPtrInst>(&I);
            if (!GEP)
                continue;
            if (!isRAMGEP(GEP, RAM))
                continue;

            collectMemUsersTransitively(GEP, RAM, DL, Out);
        }
    }
    return !Out.empty();
}

static void flattenAdds(Value *V, SmallVectorImpl<Value *> &Out)
{
    // Treat sub as add with negated RHS where trivially available.
    Value *X = V;
    SmallVector<Value *, 8> Stack;
    Stack.push_back(X);
    while (!Stack.empty())
    {
        Value *Cur = Stack.pop_back_val();
        if (auto *I = dyn_cast<Instruction>(Cur))
        {
            if (I->getOpcode() == Instruction::Add)
            {
                Stack.push_back(I->getOperand(0));
                Stack.push_back(I->getOperand(1));
                continue;
            }
            if (I->getOpcode() == Instruction::Sub)
            {
                // a - b => a + (-b) when b is constant; otherwise keep as is
                if (auto *CB = dyn_cast<ConstantInt>(I->getOperand(1)))
                {
                    Stack.push_back(I->getOperand(0));
                    APInt Neg = -(CB->getValue().sext(64));
                    Out.push_back(ConstantInt::get(I->getType(), Neg));
                    continue;
                }
            }
        }
        Out.push_back(Cur);
    }
}

static bool isLoadFromRsp(Value *V, Argument *RspArg)
{
    if (auto *LI = dyn_cast<LoadInst>(V))
    {
        return LI->getPointerOperand() == RspArg;
    }
    return false;
}

// Return the expression Rem where Idx = RSP + Rem (best-effort), and set HasRsp.
// Best-effort extractor that drops exactly one RSP term from an add/sub tree.
Value *decomposeIdxMinusRsp(Value *Idx, Argument *RspArg, bool &HasRsp, Instruction *InsertPt)
{
    HasRsp = false;
    SmallVector<Value *, 8> Work;
    flattenAdds(Idx, Work);

    LLVMContext &Ctx = InsertPt->getContext();
    IRBuilder<> B(InsertPt);
    Type *I64 = Type::getInt64Ty(Ctx);

    APInt ConstSum(64, 0, /*signed*/ true);
    SmallVector<Value *, 8> DynTerms;

    bool DroppedRsp = false;
    for (Value *T : Work)
    {
        // Constants
        if (auto *C = dyn_cast<ConstantInt>(T))
        {
            ConstSum += C->getValue().sext(64);
            continue;
        }
        // Try to see if T contains load from %rsp (directly).
        if (!DroppedRsp && isLoadFromRsp(T, RspArg))
        {
            DroppedRsp = true;
            HasRsp = true;
            continue;
        }
        DynTerms.push_back(T);
    }

    Value *Rem = ConstantInt::get(I64, ConstSum);
    for (Value *T : DynTerms)
    {
        Value *TT = T;
        if (TT->getType() != I64)
            TT = B.CreateSExtOrTrunc(TT, I64, "ext");
        Rem = B.CreateAdd(Rem, TT, "add");
    }
    return Rem;
}

PreservedAnalyses CanonicalizeStackPass::run(Function &F, FunctionAnalysisManager &AM)
{
    Module *M = F.getParent();
    const DataLayout &DL = M->getDataLayout();

    // Identify RAM global heuristically: look for a GlobalVariable named "RAM"
    // or any GlobalVariable used as base of a GEP with element type [0 x i8].
    GlobalVariable *RAM = findRAMGlobal(*M);
    if (!RAM)
        return PreservedAnalyses::all();

    // Identify the %rsp argument: by convention, the 5th parameter (index 4).
    Argument *RspArg = getRspArgument(F);
    if (!RspArg || !RspArg->getType()->isPointerTy())
        return PreservedAnalyses::all();

    // Collect candidate sites.
    SmallVector<Site, 32> Sites;
    if (!collectSites(F, *RAM, *RspArg, DL, Sites))
        return PreservedAnalyses::all();

    // Decompose each site index into RSP + Rem and normalize Rem to i64.
    LLVMContext &Ctx = F.getContext();
    IntegerType *I64 = Type::getInt64Ty(Ctx);
    for (auto &S : Sites)
    {
        S.Rem = decomposeIdxMinusRsp(S.Idx, RspArg, S.HasRsp, S.GEP);
        if (!S.HasRsp)
            continue;
        if (S.Rem->getType() != I64)
        {
            IRBuilder<> B(S.GEP);
            S.Rem = B.CreateSExtOrTrunc(S.Rem, I64, "rem.i64");
        }
    }

    // Filter only sites that actually used RSP.
    SmallVector<Site, 32> RspSites;
    for (auto &S : Sites)
        if (S.HasRsp)
            RspSites.push_back(S);
    if (RspSites.empty())
        return PreservedAnalyses::all();

    outs() << "CanonicalizeStackPass: found " << RspSites.size() << " sites\n";

    // Partition into bounded vs unknown using SCEV.
    auto &SE = AM.getResult<ScalarEvolutionAnalysis>(F);
    APInt GlobalMin(64, 0, /*signed*/ true);
    APInt GlobalMax(64, 0, /*signed*/ true);
    bool First = true;
    uint64_t MaxAccess = 1;

    SmallVector<Site, 32> BoundedSites, UnknownSites;

    for (auto &S : RspSites)
    {
        S.debug_print();

        // Build SCEV for Rem and strip sign-extend to query on native width.
        const SCEV *RS = SE.getSCEV(S.Rem);
        if (auto *SX = dyn_cast<SCEVSignExtendExpr>(RS))
            RS = SX->getOperand(); // query on source bit-width first

        // Use the signed or unsigned range as appropriate.
        ConstantRange CR = SE.getSignedRange(RS);

        // Classify: keep only tight, non-wrapped ranges for sizing; else mark unknown.
        auto IsUseful = [&](const ConstantRange &R)
        {
            if (R.isFullSet() || R.isEmptySet())
                return false; // trivial cases
            if (R.isWrappedSet())
                return false;                                             // spans across sign
            APInt Span = R.getUpper().sext(128) - R.getLower().sext(128); // half-open
            // Example threshold: ignore ranges spanning more than, say, 1MB in bytes.
            return Span.ult(APInt(128, 1 << 20));
        };

        if (!IsUseful(CR))
        {
            UnknownSites.push_back(S);
            continue; // do not use for sizing or rewriting
        }

        // Derive per-site min/max.
        APInt ThisMin = CR.isFullSet()
                            ? cast<ConstantInt>(S.Rem)->getValue().sext(64)
                            : CR.getSignedMin();
        APInt ThisMax = CR.isFullSet()
                            ? cast<ConstantInt>(S.Rem)->getValue().sext(64)
                            : CR.getSignedMax();

        // Track span and access width only from bounded sites.
        MaxAccess = std::max<uint64_t>(MaxAccess, S.AccessBytes);

        outs() << "  Bounded site range: [" << ThisMin << ", " << ThisMax << "]\n";
        outs() << "  AccessBytes: " << S.AccessBytes << "\n";

        if (First)
        {
            GlobalMin = ThisMin;
            GlobalMax = ThisMax;
            First = false;
        }
        else
        {
            if (ThisMin.slt(GlobalMin))
                GlobalMin = ThisMin;
            if (ThisMax.sgt(GlobalMax))
                GlobalMax = ThisMax;
        }

        BoundedSites.push_back(S);
    }

    // If nothing bounded, do nothing (preserve original semantics).
    if (BoundedSites.empty())
        return PreservedAnalyses::all();

    // Account for width at the top end.
    if (!GlobalMax.isNegative())
    {
        GlobalMax = GlobalMax + APInt(64, MaxAccess - 1, /*signed*/ false);
    }

    // Align, size, and create %STACK as before.
    int64_t MinS = GlobalMin.getSExtValue();
    int64_t MaxS = GlobalMax.getSExtValue();
    int64_t AlignedMin = alignDown64(MinS, StackAlignBytes);
    int64_t AlignedMax = alignTo64(std::max(MaxS, MinS), StackAlignBytes);
    uint64_t Size = (uint64_t)(AlignedMax - AlignedMin);
    if (Size == 0)
        Size = StackAlignBytes;

    IRBuilder<> EntryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
    Type *I8 = Type::getInt8Ty(Ctx);
    Value *SizeVal = ConstantInt::get(I64, Size);
    AllocaInst *StackAlloca = EntryBuilder.CreateAlloca(I8, SizeVal, "STACK");
    StackAlloca->setAlignment(Align(StackAlignBytes));
    {
        MDNode *Tag = MDNode::get(Ctx, MDString::get(Ctx, "stack.canonical"));
        StackAlloca->setMetadata("stack.canonical", Tag);
    }
    int64_t BaseShift = -AlignedMin;

    auto rewriteSite = [&](Site &S)
    {
        // NewIdx = BaseShift + Rem
        IRBuilder<> B(S.MemI);
        Value *ShiftVal = ConstantInt::get(I64, BaseShift);
        Value *NewIdx = B.CreateAdd(ShiftVal, S.Rem, "stack.off");
        Value *NewPtr = B.CreateGEP(I8, StackAlloca, NewIdx, "stack.ptr"); // not inbounds

        if (auto *LI = dyn_cast<LoadInst>(S.MemI))
            LI->setOperand(0, NewPtr);
        else if (auto *SI = dyn_cast<StoreInst>(S.MemI))
            SI->setOperand(1, NewPtr);
        else if (auto *RMW = dyn_cast<AtomicRMWInst>(S.MemI))
            RMW->setOperand(0, NewPtr);
        else if (auto *CX = dyn_cast<AtomicCmpXchgInst>(S.MemI))
            CX->setOperand(0, NewPtr);
    };

    for (auto &S : BoundedSites)
    {
        rewriteSite(S);
    }
    for (auto &S : UnknownSites)
    {
        rewriteSite(S);
    }

    // Clean up dead original GEPs
    SmallPtrSet<Instruction *, 32> EraseList;
    for (auto &S : BoundedSites)
        if (S.GEP->use_empty())
            EraseList.insert(S.GEP);
    for (auto &S : UnknownSites)
        if (S.GEP->use_empty())
            EraseList.insert(S.GEP);

    for (Instruction *I : EraseList)
        I->eraseFromParent();

    return PreservedAnalyses::none();
}

// New PM plugin registration.
PassPluginLibraryInfo getCanonicalizeStackPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION, "canonicalize-stack", LLVM_VERSION_STRING,
        [](PassBuilder &PB)
        {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>)
                {
                    if (Name == "canonicalize-stack")
                    {
                        FPM.addPass(CanonicalizeStackPass());
                        return true;
                    }
                    return false;
                });
        }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return getCanonicalizeStackPassPluginInfo();
}
