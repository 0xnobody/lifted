#include "helper_state_annotations.hpp"

#include "../abi/function_state_attrs.hpp"

namespace lifted::lifter
{

namespace
{
    llvm::Error annotate_function(llvm::Module &module,
                                  llvm::StringRef name,
                                  annotation_id_t annotation_id)
    {
        auto *F = module.getFunction(name);
        if (!F)
            return llvm::Error::success();

        if (auto err = lifted::abi::set_state_form(*F, lifted::abi::state_form_t::folded))
            return err;
        return lifted::abi::set_annotation_id(*F, annotation_id);
    }
} // namespace

    llvm::Error annotate_linked_state_helpers(llvm::Module &module,
                                              BinaryContext &bin_ctx,
                                              annotation_id_t current_annotation_id)
    {
        if (auto err = annotate_function(module,
                                         "__lifted_bb_entered",
                                         bin_ctx.get_or_create_builtin_annotation(
                                             builtin_annotation_kind_t::lifted_observer_all_registers)))
            return err;
        if (auto err = annotate_function(module, "__slice_rip", current_annotation_id))
            return err;
        if (auto err = annotate_function(module, "__lifted_ext_call", current_annotation_id))
            return err;
        if (auto err = annotate_function(module, "__lifted_recursive_call", current_annotation_id))
            return err;
        return llvm::Error::success();
    }

} // namespace lifted::lifter
