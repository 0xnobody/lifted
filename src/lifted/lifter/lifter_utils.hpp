#pragma once

#include "lifter_types.hpp"

#include <llvm/ADT/AddressRanges.h>

#include <set>

namespace llvm
{
    class Function;
    class Module;
} // namespace llvm

namespace LIEF
{
    class Binary;
} // namespace LIEF

namespace lifted::lifter
{

    // ── Optimization ─────────────────────────────────────────────────────────

    /// Run always_inline on the module containing `func`, inlining all Remill
    /// semantics and helper functions marked alwaysinline.
    void inline_remill_semantics(llvm::Function *func);

    /// Run the default SCCP/CorrelatedValuePropagation/ConstMemFolding/GVN
    /// resolve pipeline on `F`.  Iterates up to 3 times until stable, then
    /// runs SimplifyCFG + ADCE + InstCombine.
    void run_default_resolve_pipeline(
        llvm::Function &F,
        const LIEF::Binary &binary,
        const std::set<llvm::AddressRange> &const_rva_ranges);

    // ── Target extraction ────────────────────────────────────────────────────

    /// Extract constant return values from an optimized slice function and
    /// classify them as INTERNAL or EXTERNAL using `ext_func_ranges`.
    ///
    /// Matches PHI + Select trees of ConstantInt return values.  Returns empty
    /// result when any return value is not constant-foldable.
    resolved_targets_result_t extract_constant_targets(
        llvm::Function &F,
        const std::set<llvm::AddressRange> &ext_func_ranges);

    /// Detect indirect jump via GOT pattern in an optimized function.
    /// Matches:  %r = load i64, ptr GEP(@RAM, 0, {const_offset_in_got})
    ///           ret i64 %r
    /// Returns an IndirectTarget with empty callee_t when found, empty result
    /// otherwise.
    resolved_targets_result_t extract_indirect_targets(
        llvm::Function &F,
        const std::set<llvm::AddressRange> &got_ranges);

    /// Classify an address as INTERNAL or EXTERNAL.
    resolved_target_t::Type classify_address(
        uint64_t addr,
        const std::set<llvm::AddressRange> &ext_func_ranges);

    /// Returns true if `addr` falls within any GOT table range.
    bool is_got_entry(uint64_t addr, const std::set<llvm::AddressRange> &got_ranges);

    /// Create a wrapper for `F` with the parameter at `pc_param_idx` removed
    /// and replaced by the concrete constant `concrete_pc`.
    ///
    /// Returns an error if `pc_param_idx` is out of bounds or the parameter
    /// type is not an integer.
    llvm::Expected<llvm::Function *> concretize_entry_pc(
        llvm::Function *F,
        unsigned pc_param_idx,
        uint64_t concrete_pc);

} // namespace lifted::lifter
