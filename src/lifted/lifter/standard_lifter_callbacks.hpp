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

namespace lifted::lifter
{

struct standard_lifter_config_t
{
    std::set<llvm::AddressRange> const_rva_ranges;
    std::set<llvm::AddressRange> got_table_rva_ranges;
    std::set<llvm::AddressRange> ext_func_rva_ranges;

    /// When non-empty, intermediate IR artifacts are written here at key
    /// points during resolve_targets (slice_pre_inline, slice_pre_opt,
    /// slice_post_opt).
    std::string artifact_dir;

    static standard_lifter_config_t from_standard_linux_binary(
        const LIEF::Binary &binary,
        std::string artifact_dir = "");
};

class StandardLifterCallbacks : public LifterCallbacks
{
  public:
    explicit StandardLifterCallbacks(standard_lifter_config_t config);

    resolved_targets_result_t resolve_targets(resolve_context_t &ctx) override;
    const standard_lifter_config_t &config() const { return config_; }

  private:
    standard_lifter_config_t config_;

    resolved_targets_result_t heuristically_extract_targets(llvm::Function &F, resolve_context_t &ctx);

    bool is_got_entry(uint64_t addr);

    static void maybe_write_artifact(std::string_view artifact_dir,
                                     std::string_view name,
                                     const llvm::Module &module);
};

} // namespace lifted::lifter
