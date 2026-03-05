#pragma once

#include "lifter_types.hpp"
#include "lift_context.hpp"
namespace llvm
{
class Function;
class Module;
} // namespace llvm

namespace LIEF
{
class Binary;
} // namespace LIEF

namespace lifted::abi
{
class CallingConvention;
} // namespace lifted::abi

namespace lifted::lifter
{

// ── resolve_context_t ─────────────────────────────────────────────────────

/// Prepared by the Lifter before calling LifterCallbacks::resolve_targets().
/// Contains the backward slice already built so the callback only needs to
/// optimize and extract targets.
struct resolve_context_t
{
    const lifted_bb_t &bb;
    uint64_t           entry_rva;
    lift_context_t    &lift_ctx;

    // Pre-built by Lifter:
    std::unique_ptr<llvm::Module> slice_module;    ///< Clone of bb_cache_module_ with helpers linked.
    llvm::Function               *slice_cfg;       ///< Backward-slice CFG, 4-param (state,rva,mem,base).
    llvm::Function               *concretized_slice; ///< Base-concretized, 3-param (state,rva,mem).
    const LIEF::Binary           &binary;          ///< For ConstantMemoryFoldingPass.
};

// ── LifterCallbacks ───────────────────────────────────────────────────────

/// Virtual interface for Lifter customisation.  All hooks have working
/// defaults.  Subclass to override specific
/// behaviour for a given obfuscator or binary family.
struct LifterCallbacks
{
    virtual ~LifterCallbacks() = default;

    // ── Target resolution ─────────────────────────────────────────────

    /// Full target resolution for a basic block.
    ///
    /// The Lifter prepares `ctx` with the backward slice already built.
    /// The Lifter prepares `ctx` with the backward slice already built.
    /// Override to use pre-extracted targets or a custom strategy
    /// (e.g. symbolic execution).  See StandardLifterCallbacks for the
    /// default inline+optimize+extract implementation.
    virtual resolved_targets_result_t resolve_targets(resolve_context_t &ctx) = 0;

    // ── Per-BB processing ─────────────────────────────────────────────

    /// Called after a BB is lifted into `func`.  Handles both observation and
    /// optimisation.  Default: run always_inline to inline Remill semantics.
    virtual void process_bb(const lifted_bb_t &bb, llvm::Function *func);

    // ── Post-lift hook ────────────────────────────────────────────────

    /// Called on the final stitched function before lift() returns.  Default
    /// is a no-op.  Override for whole-function deobfuscation passes.
    virtual void on_function_built(llvm::Function *func, lift_context_t &ctx);

    // ── Calling convention ────────────────────────────────────────────

    /// Resolve the calling convention for a callee.  Default: nullptr.
    virtual const abi::CallingConvention *resolve_cc(
        std::optional<callee_t> callee) const;

    // ── Observation hooks (all no-op by default) ──────────────────────

    /// Called after targets are resolved for a BB.
    virtual void on_targets_resolved(
        const lifted_bb_t &bb, const resolved_targets_result_t &result);

    /// Called when a block is split due to a mid-block target landing
    /// inside an existing block.
    virtual void on_block_split(bb_id_t original, bb_id_t first_half,
                                bb_id_t second_half);

    /// Called before processing the next worklist item.  Return false to skip
    /// (the block is neither lifted nor analysed).
    virtual bool should_continue_exploration(
        bb_id_t next_id, const lift_context_t &ctx) const;
};

} // namespace lifted::lifter
