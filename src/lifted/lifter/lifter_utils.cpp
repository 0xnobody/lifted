#include "lifter_utils.hpp"

#include "../abi/function_state_attrs.hpp"
#include "../binary_context.hpp"
#include "../compat/lief_compat.hpp"
#include "../opt.hpp"
#include "../passes/deobfuscation/constant_memory_folding_pass.hpp"
#include "../passes/pass_utils.hpp"

#include <glog/logging.h>

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/CorrelatedValuePropagation.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/SCCP.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>

namespace lifted::lifter
{

// ── Optimization ─────────────────────────────────────────────────────────

void inline_remill_semantics(llvm::Function *func)
{
    opt::always_inline(func->getParent());
}

void run_default_resolve_pipeline(
    llvm::Function &F,
    const LIEF::Binary &binary,
    const std::set<llvm::AddressRange> &const_rva_ranges)
{
    llvm::LoopAnalysisManager LAM;
    llvm::FunctionAnalysisManager FAM;
    llvm::CGSCCAnalysisManager CGAM;
    llvm::ModuleAnalysisManager MAM;

    llvm::PassBuilder PB;
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);

    // Initial cleanup
    {
        llvm::FunctionPassManager FPM;
        FPM.addPass(llvm::PromotePass());
        FPM.addPass(llvm::InstCombinePass());
        FPM.run(F, FAM);
    }

    // Iterative constant-propagation loop
    bool changed = true;
    for (int iter = 0; iter < 3 && changed; ++iter)
    {
        llvm::FunctionPassManager FPM;
        FPM.addPass(llvm::SCCPPass());
        FPM.addPass(llvm::CorrelatedValuePropagationPass());
        FPM.addPass(ConstantMemoryFoldingPass(binary, const_rva_ranges));
        FPM.addPass(llvm::InstCombinePass());
        FPM.addPass(llvm::GVNPass());
        llvm::PreservedAnalyses PA = FPM.run(F, FAM);
        changed = !PA.areAllPreserved();
    }

    // Final cleanup
    {
        llvm::FunctionPassManager FPM;
        FPM.addPass(llvm::SimplifyCFGPass());
        FPM.addPass(llvm::ADCEPass());
        FPM.addPass(llvm::InstCombinePass());
        FPM.run(F, FAM);
    }
}

// ── Target extraction helpers ─────────────────────────────────────────────

/// Recursively collect all ConstantInt values reachable from `V` through
/// PHI nodes and Select instructions.  Returns false if any leaf is not a
/// ConstantInt (i.e. the expression is not fully constant-foldable).
static bool collect_return_constants(
    llvm::Value *V,
    llvm::SmallPtrSetImpl<llvm::Value *> &visited,
    llvm::SmallSetVector<uint64_t, 4> &out)
{
    if (!V || !visited.insert(V).second)
        return true;

    if (auto *C = llvm::dyn_cast<llvm::ConstantInt>(V))
    {
        out.insert(C->getZExtValue());
        return true;
    }
    if (auto *Phi = llvm::dyn_cast<llvm::PHINode>(V))
    {
        for (llvm::Value *inc : Phi->incoming_values())
            if (!collect_return_constants(inc, visited, out))
                return false;
        return true;
    }
    if (auto *Sel = llvm::dyn_cast<llvm::SelectInst>(V))
    {
        return collect_return_constants(Sel->getTrueValue(), visited, out) &&
               collect_return_constants(Sel->getFalseValue(), visited, out);
    }
    return false; // unresolvable
}

llvm::SmallSetVector<uint64_t, 4> extract_constant_returns(llvm::Function &F)
{
    llvm::SmallSetVector<uint64_t, 4> rvas;
    llvm::SmallPtrSet<llvm::Value *, 16> visited;

    for (auto &BB : F)
    {
        auto *Ret = llvm::dyn_cast<llvm::ReturnInst>(BB.getTerminator());
        if (!Ret)
            continue;
        if (!collect_return_constants(Ret->getReturnValue(), visited, rvas))
            return {}; // not fully constant-foldable
    }

    return rvas;
}

llvm::Expected<llvm::Function *>
concretize_entry_pc(llvm::Function *F,
                    unsigned pc_param_idx,
                    uint64_t concrete_pc)
{
    auto *M = F->getParent();
    auto *old_fty = F->getFunctionType();

    if (pc_param_idx >= old_fty->getNumParams())
        return llvm::make_error<llvm::StringError>(
            "concretize_entry_pc: parameter index " +
                std::to_string(pc_param_idx) + " out of bounds",
            llvm::inconvertibleErrorCode());

    auto *pc_param_ty = old_fty->getParamType(pc_param_idx);
    if (!pc_param_ty->isIntegerTy())
        return llvm::make_error<llvm::StringError>(
            "concretize_entry_pc: parameter " + std::to_string(pc_param_idx) +
                " is not an integer type",
            llvm::inconvertibleErrorCode());

    std::vector<llvm::Type *> new_params;
    for (unsigned i = 0; i < old_fty->getNumParams(); ++i)
        if (i != pc_param_idx)
            new_params.push_back(old_fty->getParamType(i));

    auto *new_fty = llvm::FunctionType::get(
        old_fty->getReturnType(), new_params, old_fty->isVarArg());
    auto *new_f = llvm::Function::Create(
        new_fty, F->getLinkage(), F->getName() + "_concrete", M);
    lifted::abi::copy_lifted_state_attrs(*F, *new_f);

    auto old_attrs = F->getAttributes();
    std::vector<llvm::AttributeSet> param_attrs;
    for (unsigned i = 0; i < old_fty->getNumParams(); ++i)
        if (i != pc_param_idx)
            param_attrs.push_back(old_attrs.getParamAttrs(i));
    new_f->setAttributes(llvm::AttributeList::get(
        M->getContext(), old_attrs.getFnAttrs(), old_attrs.getRetAttrs(),
        param_attrs));

    llvm::IRBuilder<> irb(
        llvm::BasicBlock::Create(M->getContext(), "", new_f));
    std::vector<llvm::Value *> args;
    unsigned new_arg_idx = 0;
    for (unsigned i = 0; i < old_fty->getNumParams(); ++i)
    {
        if (i == pc_param_idx)
            args.push_back(llvm::ConstantInt::get(pc_param_ty, concrete_pc));
        else
            args.push_back(new_f->getArg(new_arg_idx++));
    }
    irb.CreateRet(irb.CreateCall(F, args));
    return new_f;
}

} // namespace lifted::lifter
