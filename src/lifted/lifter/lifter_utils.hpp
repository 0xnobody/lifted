#pragma once

#include "lifter_types.hpp"

#include <llvm/ADT/AddressRanges.h>
#include <llvm/ADT/SetVector.h>

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

namespace lifted
{
class BinaryContext;
} // namespace lifted

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

llvm::SmallSetVector<uint64_t, 4> extract_constant_returns(llvm::Function &F);

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
