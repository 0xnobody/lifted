#include "lifter_utils.hpp"

#include "../compat/lief_compat.hpp"
#include "../opt.hpp"
#include "../passes/deobfuscation/constant_memory_folding_pass.hpp"
#include "../passes/pass_utils.hpp"

#include <glog/logging.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/CorrelatedValuePropagation.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/SCCP.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
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

    // ── Public API ────────────────────────────────────────────────────────────

    resolved_target_t::Type classify_address(
        uint64_t addr,
        const std::set<llvm::AddressRange> &ext_func_ranges)
    {
        for (const auto &r : ext_func_ranges)
            if (r.contains(addr))
                return resolved_target_t::Type::EXTERNAL;
        return resolved_target_t::Type::INTERNAL;
    }

    bool is_got_entry(uint64_t addr, const std::set<llvm::AddressRange> &got_ranges)
    {
        for (const auto &r : got_ranges)
            if (r.contains(addr))
                return true;
        return false;
    }

    resolved_targets_result_t extract_constant_targets(
        llvm::Function &F,
        const std::set<llvm::AddressRange> &ext_func_ranges)
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

        if (rvas.empty())
            return {};

        std::vector<resolved_target_t> targets;
        for (uint64_t rva : rvas)
            targets.push_back(resolved_target_t{
                .type = classify_address(rva, ext_func_ranges),
                .dest = rva,
                .callee_info = callee_t{}});

        return resolved_targets_result_t{std::move(targets), std::nullopt};
    }

    resolved_targets_result_t extract_indirect_targets(
        llvm::Function &F,
        const std::set<llvm::AddressRange> &got_ranges)
    {
        // Match:
        //   %r = load i64, ptr GEP(@RAM, 0, {const_offset_in_got})
        //   ret i64 %r
        if (auto *ret = llvm::dyn_cast<llvm::ReturnInst>((--F.end())->getTerminator()))
        {
            if (auto *load = llvm::dyn_cast<llvm::LoadInst>(ret->getReturnValue()))
            {
                if (auto *gep = passes::isRAMGEP(load->getPointerOperand()))
                {
                    auto *offset = gep->getOperand(2);
                    if (auto *const_off = llvm::dyn_cast<llvm::ConstantInt>(offset))
                    {
                        if (is_got_entry(const_off->getZExtValue(), got_ranges))
                        {
                            DLOG(INFO) << "Resolved indirect target via GOT at offset 0x"
                                       << std::hex << const_off->getZExtValue();
                            return resolved_targets_result_t{
                                .targets = {},
                                .indirect_target = callee_t{}};
                        }
                    }
                }
            }
        }

        return {};
    }

} // namespace lifted::lifter
