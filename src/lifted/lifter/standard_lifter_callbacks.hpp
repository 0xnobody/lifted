#pragma once

#include "lifter_callbacks.hpp"
#include "lifter_types.hpp"
#include "lifter_utils.hpp"

#include <llvm/ADT/AddressRanges.h>
#include <llvm/Support/Error.h>

#include <set>
#include <string>

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

// ── standard_lifter_config_t ──────────────────────────────────────────────

struct standard_lifter_config_t
{
    const LIEF::Binary *binary = nullptr;

    std::set<llvm::AddressRange> const_rva_ranges;
    std::set<llvm::AddressRange> got_table_rva_ranges;
    std::set<llvm::AddressRange> ext_func_rva_ranges;

    const abi::CallingConvention *default_cc = nullptr;

    /// When non-empty, intermediate IR artifacts are written here at key
    /// points during resolve_targets (slice_pre_inline, slice_pre_opt,
    /// slice_post_opt).
    std::string artifact_dir;
};

// ── StandardLifterCallbacks ───────────────────────────────────────────────

class StandardLifterCallbacks : public LifterCallbacks
{
public:
    explicit StandardLifterCallbacks(standard_lifter_config_t config);

    resolved_targets_result_t resolve_targets(resolve_context_t &ctx) override;
    const abi::CallingConvention *resolve_cc(
        std::optional<callee_t> callee) const override;

    const standard_lifter_config_t &config() const { return config_; }

    /// Create a wrapper for `F` with the parameter at `pc_param_idx` removed
    /// and replaced by the concrete constant `concrete_pc`.
    ///
    /// Returns an error if `pc_param_idx` is out of bounds or the parameter
    /// type is not an integer.
    static llvm::Expected<llvm::Function *> concretize_entry_pc(
        llvm::Function *F,
        unsigned        pc_param_idx,
        uint64_t        concrete_pc);

private:
    standard_lifter_config_t config_;

    /// Write `module` as LLVM IR to `artifact_dir/<name>.ll`.
    /// No-op when artifact_dir is empty.
    static void maybe_write_artifact(std::string_view artifact_dir,
                                     std::string_view name,
                                     const llvm::Module &module);
};

} // namespace lifted::lifter
