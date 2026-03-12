#pragma once

#include "../binary_context.hpp"

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/Error.h>

namespace lifted::abi
{

    enum class state_form_t
    {
        folded,
        unfolded,
    };

    llvm::StringRef to_string(state_form_t form);

    bool has_state_form(const llvm::Function &F);
    llvm::Expected<state_form_t> get_state_form(const llvm::Function &F);
    llvm::Error set_state_form(llvm::Function &F, state_form_t form);

    bool has_annotation_id_attr(const llvm::Function &F);
    llvm::Expected<annotation_id_t> get_annotation_id(const llvm::Function &F);
    llvm::Error set_annotation_id(llvm::Function &F, annotation_id_t annotation_id);

    bool has_lifted_state_attrs(const llvm::Function &F);
    llvm::Error require_lifted_state_attrs(const llvm::Function &F);
    void copy_lifted_state_attrs(const llvm::Function &src, llvm::Function &dst);

    /// Functions that semantically participate in lifted-state transforms.
    /// Under the current contract this is driven by lifted IR annotations, while
    /// still excluding trivial register helpers like __extract_* / __store_*.
    bool is_state_attr_candidate(const llvm::Function &F);

} // namespace lifted::abi
