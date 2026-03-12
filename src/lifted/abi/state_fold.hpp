#pragma once

#include "calling_convention.hpp"
#include "function_state_attrs.hpp"

#include <functional>

#include <llvm/IR/Argument.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/Error.h>

namespace lifted::abi
{

    bool is_folded_function(const llvm::Function *F);
    bool is_unfolded_function(const llvm::Function *F);

    /// True if the function's State is conceptually passed by value.
    ///
    /// Folded functions infer this from param-0's byval attribute.
    /// Unfolded functions infer it from the register parameter shape:
    ///   - i64  register params => byval snapshot
    ///   - ptr  register params => byptr/write-back
    bool is_byval_state(const llvm::Function *F);

    llvm::Argument *getRegisterArgument(llvm::Function *F,
                                        const CallingConvention &CC,
                                        ABIRegister Reg);

    /// True if unfolded register parameters are exposed as pointers.
    bool isRegisterParamByPointer(const llvm::Function *F);

    /// Create F.unfolded from a folded, explicitly annotated lifted-state function.
    /// The new function keeps the source annotation_id and flips lifted.state_form.
    llvm::Expected<llvm::Function *> unfold_function_state(llvm::Function *F,
                                                           const CallingConvention &CC);
    llvm::Expected<llvm::Function *> unfold_function_state(llvm::Function *F,
                                                           const lifted::BinaryContext &bin_ctx);

    /// Recursively unfold all reachable lifted-state callees, then unfold F.
    llvm::Expected<llvm::Function *> unfold_function_state_recursive(
        llvm::Function *F,
        const CallingConvention &CC,
        std::function<llvm::Expected<const CallingConvention *>(llvm::Function &)> resolve_cc);
    llvm::Expected<llvm::Function *> unfold_function_state_recursive(
        llvm::Function *F,
        const lifted::BinaryContext &bin_ctx);

    /// Create F.folded from an unfolded, explicitly annotated lifted-state function.
    /// The new function keeps the source annotation_id and flips lifted.state_form.
    llvm::Expected<llvm::Function *> fold_function_state(llvm::Function *F,
                                                         const CallingConvention &CC);
    llvm::Expected<llvm::Function *> fold_function_state(llvm::Function *F,
                                                         const lifted::BinaryContext &bin_ctx);

    /// Recursively fold all reachable lifted-state callees, then fold F.
    llvm::Expected<llvm::Function *> fold_function_state_recursive(
        llvm::Function *F,
        const CallingConvention &CC,
        std::function<llvm::Expected<const CallingConvention *>(llvm::Function &)> resolve_cc);
    llvm::Expected<llvm::Function *> fold_function_state_recursive(
        llvm::Function *F,
        const lifted::BinaryContext &bin_ctx);

} // namespace lifted::abi
