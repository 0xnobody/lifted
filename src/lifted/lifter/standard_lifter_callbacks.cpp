#include "standard_lifter_callbacks.hpp"
#include "lifter_utils.hpp"

#include "../abi/calling_convention.hpp"
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

        config.binary = &binary;

        std::set<llvm::AddressRange> got_table_rva_ranges;
        if (auto got_range = utils::get_section_bounds(binary, ".got"))
            config.got_table_rva_ranges.insert(*got_range);

        std::set<llvm::AddressRange> ext_func_rva_ranges;
        if (auto plt_range = utils::get_section_bounds(binary, ".plt.sec"))
            config.ext_func_rva_ranges.insert(*plt_range);

        auto CC = abi::SystemVx64CC();
        config.default_cc = &CC;
        config.artifact_dir = artifact_dir;

        return config;
    }

    // ── StandardLifterCallbacks ─────────────────────────────────────────────────

    StandardLifterCallbacks::StandardLifterCallbacks(standard_lifter_config_t config)
        : config_(std::move(config))
    {
    }

    const abi::CallingConvention *
    StandardLifterCallbacks::resolve_cc(std::optional<callee_t> callee) const
    {
        if (callee && callee->cc)
            return callee->cc;
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

    /*static*/ llvm::Expected<llvm::Function *>
    StandardLifterCallbacks::concretize_entry_pc(llvm::Function *F,
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
            new_fty, F->getLinkage(), F->getName() + ".concrete", M);

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
        if (!config_.binary)
            return {};
        run_default_resolve_pipeline(*F, *config_.binary, config_.const_rva_ranges);

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
        if (result)
            return result;

        result = extract_indirect_targets(*analysis_func, config_.got_table_rva_ranges);
        if (result)
            return result;

        DLOG(WARNING) << "resolve_targets: failed to resolve targets for BB 0x"
                      << std::hex << ctx.bb.id;
        return {};
    }

} // namespace lifted::lifter
