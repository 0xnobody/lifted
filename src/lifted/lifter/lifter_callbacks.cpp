#include "lifter_callbacks.hpp"
#include "lifter_utils.hpp"

#include "../abi/calling_convention.hpp"
#include "../utils.hpp"

#include <llvm/IR/Function.h>

namespace lifted::lifter
{

// ── LifterCallbacks default implementations ─────────────────────────────────

void LifterCallbacks::process_bb(const lifted_bb_t &bb, llvm::Function *func)
{
    // Default: always-inline to collapse Remill semantics into the BB function.
    inline_remill_semantics(func);
}

void LifterCallbacks::on_function_built(llvm::Function * /*func*/,
                                        lift_context_t & /*ctx*/)
{
}

const abi::CallingConvention *
LifterCallbacks::resolve_cc(std::optional<callee_t> /*callee*/) const
{
    return nullptr;
}

void LifterCallbacks::on_targets_resolved(const lifted_bb_t & /*bb*/,
                                          const resolved_targets_result_t & /*result*/)
{
}

void LifterCallbacks::on_block_split(bb_id_t /*original*/,
                                     bb_id_t /*first_half*/,
                                     bb_id_t /*second_half*/)
{
}

bool LifterCallbacks::should_continue_exploration(bb_id_t       /*next_id*/,
                                                  const lift_context_t & /*ctx*/) const
{
    return true;
}

} // namespace lifted::lifter
