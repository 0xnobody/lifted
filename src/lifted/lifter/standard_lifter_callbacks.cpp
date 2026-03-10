#include "standard_lifter_callbacks.hpp"
#include "lifter_utils.hpp"

#include "../abi/calling_convention.hpp"
#include "../binary_context.hpp"
#include "../opt.hpp"
#include "../utils.hpp"
#include "../abi/systemv_x64.hpp"

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

        config.default_cc = &abi::SystemVx64CC::get();
        config.artifact_dir = std::move(artifact_dir);

        return config;
    }

    // ── StandardLifterCallbacks ─────────────────────────────────────────────────

    StandardLifterCallbacks::StandardLifterCallbacks(standard_lifter_config_t config)
        : config_(std::move(config))
    {
    }

    const abi::CallingConvention *
    StandardLifterCallbacks::resolve_cc(const lifted::fnc_annotation_t *ann) const
    {
        if (ann && ann->cc)
            return ann->cc;
        return config_.default_cc;
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

    // ── StandardLifterCallbacks::resolve_targets ────────────────────────────────

    resolved_targets_result_t
    StandardLifterCallbacks::resolve_targets(resolve_context_t &ctx)
    {
        llvm::Module *M = ctx.slice_module.get();
        llvm::Function *F = ctx.concretized_slice;
        if (!M || !F)
            return {};

        maybe_write_artifact(config_.artifact_dir, "slice_pre_inline", *M);

        // Step 1 – inline.
        inline_remill_semantics(F);

        maybe_write_artifact(config_.artifact_dir, "slice_pre_opt", *M);

        // Step 2 – pipeline.
        run_default_resolve_pipeline(*F, ctx.bin_ctx.binary(), config_.const_rva_ranges);

        maybe_write_artifact(config_.artifact_dir, "slice_post_opt", *M);

        // Step 3 – replace __remill_function placeholder with our slice.
        auto *remill_fn = M->getFunction("__remill_function");
        if (remill_fn)
        {
            remill_fn->replaceAllUsesWith(F);
            F->addFnAttr(llvm::Attribute::AlwaysInline);
        }

        // Step 4 – concretize the entry PC into __slice_rip.
        auto *slice_rip = M->getFunction("__slice_rip");
        if (!slice_rip)
        {
            DLOG(WARNING) << "resolve_targets: __slice_rip not found for BB 0x"
                          << std::hex << ctx.bb.id;
            return {};
        }

        // __slice_rip signature: (State state, uint64_t rsp, addr_t curr_pc, Memory*)
        // curr_pc is at parameter index 2.
        auto analysis_func_or = concretize_entry_pc(slice_rip, 2, ctx.entry_rva);
        if (!analysis_func_or)
        {
            DLOG(WARNING) << "resolve_targets: concretize_entry_pc failed for BB 0x"
                          << std::hex << ctx.bb.id << ": "
                          << llvm::toString(analysis_func_or.takeError());
            return {};
        }
        auto *analysis_func = *analysis_func_or;
        slice_rip->addFnAttr(llvm::Attribute::AlwaysInline);

        // Step 5 – inline again + O2.
        opt::always_inline(M);
        opt::default_opt(M, llvm::OptimizationLevel::O2);

        // Step 6 – extract targets.
        auto result = extract_constant_targets(*analysis_func,
                                               config_.ext_func_rva_ranges);
        if (!result)
            result = extract_indirect_targets(*analysis_func, config_.got_table_rva_ranges);
        if (!result)
            DLOG(WARNING) << "resolve_targets: failed to resolve targets for BB 0x"
                          << std::hex << ctx.bb.id;

        // Step 7 – direct call-to-entry is self-recursion, not a normal internal edge.
        if (ctx.bb.terminating_category.has_value() &&
            *ctx.bb.terminating_category ==
                remill::Instruction::kCategoryDirectFunctionCall)
        {
            for (auto &target : result.targets)
            {
                if (target.type == resolved_target_t::Type::INTERNAL &&
                    target.dest == ctx.entry_rva)
                {
                    target.type = resolved_target_t::Type::RECURSIVE;
                }
            }
        }

        // Step 8 – name resolution for EXTERNAL targets.
        // For each external target, look up the symbol name in BinaryContext and
        // create/reuse an fnc_annotation_t so the lifter can generate named stubs.
        for (auto &target : result.targets)
        {
            if (target.type == resolved_target_t::Type::EXTERNAL)
            {
                auto name_opt = ctx.bin_ctx.symbol_name_at_rva(target.dest);
                if (name_opt)
                {
                    const fnc_annotation_t *ann = ctx.bin_ctx.get_by_name(*name_opt);
                    if (!ann)
                    {
                        auto new_ann  = std::make_unique<fnc_annotation_t>();
                        new_ann->name = *name_opt;
                        // cc left nullptr — resolve_cc falls back to config_.default_cc
                        annotation_id_t id = ctx.bin_ctx.create_ext_call(target.dest, std::move(new_ann));
                        ann                = ctx.bin_ctx.get_by_id(id);
                    }
                    target.annotation = ann;
                }
                // annotation remains nullptr if no symbol found — unnamed ext call
            }
        }

        // For standard call instructions, signal the lifter to also lift the
        // return site (the instruction immediately after the call).  Custom
        // callbacks override this for obfuscated call patterns (push+jmp, etc.)
        // or leave it unset when the call is non-returning.
        if (ctx.bb.rva_range.has_value() &&
            ctx.bb.terminating_category.has_value() &&
            (*ctx.bb.terminating_category ==
                 remill::Instruction::kCategoryDirectFunctionCall ||
             *ctx.bb.terminating_category ==
                 remill::Instruction::kCategoryIndirectFunctionCall))
        {
            result.return_continuation =
                static_cast<bb_id_t>(ctx.bb.rva_range->end());
        }

        // For `ret`-terminated blocks, signal that this block exits by
        // returning to its caller. The stitched CFG uses a normal function return
        // (not dead_end) as the switch default for these blocks.
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
