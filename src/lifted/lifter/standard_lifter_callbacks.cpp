#include "standard_lifter_callbacks.hpp"
#include "lifter_utils.hpp"

#include "../abi/function_state_attrs.hpp"
#include "../abi/state_fold.hpp"
#include "../binary_context.hpp"
#include "../opt.hpp"
#include "../passes/pass_utils.hpp"
#include "../utils.hpp"

#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <glog/logging.h>

namespace lifted::lifter
{
standard_lifter_config_t standard_lifter_config_t::from_standard_linux_binary(
    const LIEF::Binary &binary,
    std::string artifact_dir)
{
    standard_lifter_config_t config;

    if (auto got_range = utils::get_section_bounds(binary, ".got"))
        config.got_table_rva_ranges.insert(*got_range);

    if (auto plt_range = utils::get_section_bounds(binary, ".plt.sec"))
        config.ext_func_rva_ranges.insert(*plt_range);

    config.artifact_dir = std::move(artifact_dir);
    return config;
}

// ── StandardLifterCallbacks ─────────────────────────────────────────────────

StandardLifterCallbacks::StandardLifterCallbacks(standard_lifter_config_t config)
    : config_(std::move(config))
{
}

void StandardLifterCallbacks::maybe_write_artifact(std::string_view artifact_dir,
                                                   std::string_view name,
                                                   const llvm::Module &module)
{
    if (artifact_dir.empty())
        return;
    std::string path = std::string(artifact_dir) + "/" + std::string(name) + ".ll";
    utils::output_to_file(path, &const_cast<llvm::Module &>(module));
}

resolved_targets_result_t StandardLifterCallbacks::heuristically_extract_targets(llvm::Function &F, resolve_context_t &ctx)
{
    resolved_targets_result_t result;

    auto entry_anno = ctx.bin_ctx.get_by_id(ctx.lift_ctx.entry_annotation_id);

    auto ensure_external_annotation = [&](uint64_t dest) -> annotation_id_t
    {
        if (auto anno_id = ctx.bin_ctx.get_ext_call(dest); anno_id != INVALID_ANNOTATION_ID)
        {
            return anno_id;
        }
        std::optional<std::string> name_opt = ctx.bin_ctx.symbol_name_at_rva(dest);
        if (name_opt)
        {
            if (auto anno_id = ctx.bin_ctx.get_by_name(*name_opt); anno_id != INVALID_ANNOTATION_ID)
            {
                return anno_id;
            }
        }

        auto ann = std::make_unique<fnc_annotation_t>();
        ann->name = name_opt.value_or("ext_auto_" + llvm::utohexstr(dest));
        ann->cc = entry_anno->cc;

        return ctx.bin_ctx.create_ext_call(dest, std::move(ann));
    };

    auto classify_address = [&](uint64_t addr) -> resolved_target_t::Type
    {
        if (ctx.bb.terminating_category.has_value() &&
            *ctx.bb.terminating_category ==
                remill::Instruction::kCategoryDirectFunctionCall)
        {
            if (addr == ctx.entry_rva)
            {
                return resolved_target_t::Type::RECURSIVE;
            }
        }

        for (const auto &r : config_.ext_func_rva_ranges)
            if (r.contains(addr))
                return resolved_target_t::Type::EXTERNAL;
        return resolved_target_t::Type::INTERNAL;
    };

    auto dests = extract_constant_returns(F);

    if (!dests.empty())
    {
        for (auto dest : dests)
        {
            result.targets.push_back(resolved_target_t{
                .type = classify_address(dest),
                .dest = dest,
                .annotation_id = ensure_external_annotation(dest)});
        }

        return result;
    }

    auto ensure_indirect_annotation = [&]() -> annotation_id_t
    {
        if (auto anno_id = ctx.bin_ctx.get_indr_call(ctx.bb.id); anno_id != INVALID_ANNOTATION_ID)
        {
            return anno_id;
        }

        auto ann = std::make_unique<fnc_annotation_t>();
        ann->name = "indr_dispatch_" + llvm::utohexstr(ctx.bb.id);
        ann->cc = entry_anno->cc;

        return ctx.bin_ctx.create_indr_call(ctx.bb.id, std::move(ann));
    };

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
                    if (is_got_entry(const_off->getZExtValue()))
                    {
                        DLOG(INFO) << "Resolved indirect target via GOT at offset 0x"
                                   << std::hex << const_off->getZExtValue();

                        result.indirect_annotation_id = ensure_indirect_annotation();
                    }
                }
            }
        }
    }

    return result;
}

bool StandardLifterCallbacks::is_got_entry(uint64_t addr)
{
    for (const auto &r : config_.got_table_rva_ranges)
        if (r.contains(addr))
            return true;
    return false;
}

resolved_targets_result_t StandardLifterCallbacks::resolve_targets(resolve_context_t &ctx)
{
    llvm::Module *M = ctx.slice_module.get();
    llvm::Function *F = ctx.concretized_slice;

    std::string artifact_prefix = "bb_" + llvm::utohexstr(ctx.bb.id) + "_slice_";

    maybe_write_artifact(config_.artifact_dir, artifact_prefix + "pre_inline", *M);

    inline_remill_semantics(F);

    auto *remill_fn = M->getFunction("__remill_function");
    if (remill_fn)
    {
        remill_fn->replaceAllUsesWith(F);
        F->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    auto *slice_rip = M->getFunction("__slice_rip");
    if (!slice_rip)
    {
        DLOG(WARNING) << "resolve_targets: __slice_rip not found for BB 0x"
                      << std::hex << ctx.bb.id;
        return resolved_targets_result_t{};
    }

    auto analysis_func_or = concretize_entry_pc(slice_rip, 2, ctx.entry_rva);
    if (!analysis_func_or)
    {
        DLOG(WARNING) << "resolve_targets: concretize_entry_pc failed for BB 0x"
                      << std::hex << ctx.bb.id << ": "
                      << llvm::toString(analysis_func_or.takeError());
        return resolved_targets_result_t{};
    }
    llvm::Function *analysis_func = *analysis_func_or;
    slice_rip->addFnAttr(llvm::Attribute::AlwaysInline);

    maybe_write_artifact(config_.artifact_dir, artifact_prefix + "pre_opt", *M);

    auto unfolded_or = abi::unfold_function_state_recursive(analysis_func, ctx.bin_ctx);
    if (!unfolded_or)
    {
        DLOG(WARNING) << "resolve_targets: unfold_function_state_recursive failed for BB 0x"
                      << std::hex << ctx.bb.id << ": "
                      << llvm::toString(unfolded_or.takeError());
        return resolved_targets_result_t{};
    }
    analysis_func = *unfolded_or;
    analysis_func->setLinkage(llvm::GlobalValue::ExternalLinkage);

    maybe_write_artifact(config_.artifact_dir, artifact_prefix + "post_unfold", *M);

    opt::always_inline(M);

    run_default_resolve_pipeline(*analysis_func, ctx.bin_ctx.binary(), config_.const_rva_ranges);
    opt::always_inline(M);
    opt::default_opt(M, llvm::OptimizationLevel::O2);

    maybe_write_artifact(config_.artifact_dir, artifact_prefix + "post_opt", *M);

    auto result = heuristically_extract_targets(*analysis_func, ctx);
    if (!result)
        DLOG(WARNING) << "resolve_targets: failed to resolve targets for BB 0x"
                      << std::hex << ctx.bb.id;

    if (ctx.bb.terminating_category.has_value() &&
        *ctx.bb.terminating_category ==
            remill::Instruction::kCategoryFunctionReturn)
    {
        result.targets.push_back(
            {resolved_target_t::Type::RETURN_TO_CALLER, /*dest=*/0});
    }

    return result;
}

} // namespace lifted::lifter
