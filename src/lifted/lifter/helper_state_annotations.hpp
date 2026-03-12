#pragma once

#include "../binary_context.hpp"

#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

namespace lifted::lifter
{

    /// Attach lifted.state_form + lifted.annotation_id attrs to linked helper
    /// functions that semantically participate in state folding/unfolding.
    llvm::Error annotate_linked_state_helpers(llvm::Module &module,
                                              BinaryContext &bin_ctx,
                                              annotation_id_t current_annotation_id);

} // namespace lifted::lifter
