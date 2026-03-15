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

namespace
{
std::optional<resolved_target_t> resolve_direct_call_target(resolve_context_t &ctx,
                                                            uint64_t dest)
{
    if (dest == ctx.entry_rva)
    {
        return resolved_target_t{
            .type = resolved_target_t::Type::RECURSIVE,
            .dest = dest,
            .annotation_id = std::nullopt,
        };
    }

    const auto *entry_anno = ctx.bin_ctx.get_by_id(ctx.lift_ctx.entry_annotation_id);
    if (!entry_anno || !entry_anno->cc)
        return std::nullopt;

    std::optional<std::string> name_opt = ctx.bin_ctx.symbol_name_at_rva(dest);
    std::optional<std::string_view> resolved_name;
    if (name_opt)
        resolved_name = *name_opt;

    return resolved_target_t{
        .type = resolved_target_t::Type::EXTERNAL,
        .dest = dest,
        .annotation_id = ctx.bin_ctx.resolve_direct_call_annotation(
            ctx.bb.id, dest, resolved_name, *entry_anno->cc),
    };
}
} // namespace

std::optional<resolved_targets_result_t> StandardLifterCallbacks::hint_resolve_targets(
    resolve_context_t &ctx)
{
    resolved_targets_result_t result;

    // Fast path for normal calls:
    // CALL ext_fnc
    // <-- Edge to here from synthetic block
    if (ctx.synthetic_info && ctx.synthetic_predecessor_bb)
    {
        if (ctx.synthetic_info->type == synthetic_block_info_t::Type::INDIRECT)
            return std::nullopt;

        const lifted_bb_t &pred = *ctx.synthetic_predecessor_bb;
        if (*pred.terminating_category != remill::Instruction::kCategoryDirectFunctionCall || !pred.static_continuation_rva)
        {
            return std::nullopt;
        }

        result.targets.push_back({
            .type = resolved_target_t::Type::INTERNAL,
            .dest = *pred.static_continuation_rva,
            .annotation_id = std::nullopt,
        });
        return result;
    }

    if (ctx.bb.type != lifted_bb_t::Type::REAL)
    {
        return std::nullopt;
    }

    switch (*ctx.bb.terminating_category)
    {
    case remill::Instruction::kCategoryNormal:
        // Fallthrough
        result.targets.push_back({
            .type = resolved_target_t::Type::INTERNAL,
            .dest = *ctx.bb.static_target_rva,
            .annotation_id = std::nullopt,
        });
        return result;
    case remill::Instruction::kCategoryDirectJump:
        if (!ctx.bb.static_target_rva)
            return std::nullopt;
        result.targets.push_back({
            .type = resolved_target_t::Type::INTERNAL,
            .dest = *ctx.bb.static_target_rva,
            .annotation_id = std::nullopt,
        });
        return result;
    case remill::Instruction::kCategoryConditionalBranch:
        if (!ctx.bb.static_target_rva || !ctx.bb.static_continuation_rva)
            return std::nullopt;
        result.targets.push_back({
            .type = resolved_target_t::Type::INTERNAL,
            .dest = *ctx.bb.static_target_rva,
            .annotation_id = std::nullopt,
        });
        result.targets.push_back({
            .type = resolved_target_t::Type::INTERNAL,
            .dest = *ctx.bb.static_continuation_rva,
            .annotation_id = std::nullopt,
        });
        return result;
    case remill::Instruction::kCategoryDirectFunctionCall:
        if (!ctx.bb.static_target_rva)
            return std::nullopt;
        if (auto target = resolve_direct_call_target(ctx, *ctx.bb.static_target_rva))
        {
            result.targets.push_back(*target);
            return result;
        }
        return std::nullopt;
    case remill::Instruction::kCategoryFunctionReturn:
        result.targets.push_back({
            .type = resolved_target_t::Type::RETURN_TO_CALLER,
            .dest = 0,
            .annotation_id = std::nullopt,
        });
        return result;
    default:
        return std::nullopt;
    }
}

resolved_targets_result_t StandardLifterCallbacks::heuristically_extract_targets(llvm::Function &F, resolve_context_t &ctx)
{
    resolved_targets_result_t result;

    auto dests = extract_constant_returns(F);
    if (!dests.empty())
    {
        if (!ctx.bb.terminating_category)
            return result;

        for (auto dest : dests)
        {
            switch (*ctx.bb.terminating_category)
            {
            case remill::Instruction::kCategoryDirectFunctionCall:
                if (auto target = resolve_direct_call_target(ctx, dest))
                {
                    result.targets.push_back(*target);
                    break;
                }
                return resolved_targets_result_t{};
            case remill::Instruction::kCategoryFunctionReturn:
                result.targets.push_back({
                    .type = resolved_target_t::Type::RETURN_TO_CALLER,
                    .dest = 0,
                    .annotation_id = std::nullopt,
                });
                break;
            default:
                result.targets.push_back({
                    .type = resolved_target_t::Type::INTERNAL,
                    .dest = dest,
                    .annotation_id = std::nullopt,
                });
                break;
            }
        }
        return result;
    }

    const auto *entry_anno = ctx.bin_ctx.get_by_id(ctx.lift_ctx.entry_annotation_id);
    auto ensure_indirect_annotation = [&](std::optional<uint64_t> slot_addr)
        -> std::optional<annotation_id_t>
    {
        if (!entry_anno || !entry_anno->cc)
            return std::nullopt;

        std::optional<std::string> name_opt;
        if (slot_addr)
            name_opt = ctx.bin_ctx.import_name_for_slot(*slot_addr);
        std::optional<std::string_view> import_name;
        if (name_opt)
            import_name = *name_opt;
        return ctx.bin_ctx.resolve_indirect_call_annotation(
            ctx.bb.id, import_name, *entry_anno->cc);
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
                    uint64_t slot_addr = const_off->getZExtValue();
                    if (is_got_entry(slot_addr))
                    {
                        DLOG(INFO) << "Resolved indirect target via GOT at offset 0x"
                                   << std::hex << slot_addr;

                        result.indirect_annotation_id =
                            ensure_indirect_annotation(slot_addr);
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
        result.targets.push_back({
            .type = resolved_target_t::Type::RETURN_TO_CALLER,
            .dest = 0,
            .annotation_id = std::nullopt,
        });
    }

    return result;
}

} // namespace lifted::lifter
