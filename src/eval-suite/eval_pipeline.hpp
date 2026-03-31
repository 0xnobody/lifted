#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>

#include "lifter/lifter_types.hpp"
#include "mutation_campaign.hpp"
#include "pipeline/deep_dive.hpp"
#include "pipeline/pipeline.hpp"
#include "visualization/cfg_data.hpp"
namespace lifted::eval
{

// Result of a single lift+verify run.
struct LiftAndVerifyResult
{
    std::optional<lifter::lift_stats_t> lift_stats;    // populated on successful lift
    std::optional<pipeline::PipelineReport> report;    // null only if lifting failed
    std::optional<pipeline::DeepDiveResult> deep_dive; // null if no divergence or skipped
    std::optional<visualization::CfgSnapshot> cfg;     // populated on successful lift
    bool lift_failed = false;
    std::string lift_error; // populated when lift_failed
};

// Result of the full two-stage lift+verify run.
// Stage 1: raw lifted IR vs. native binary (Unicorn), RAW_STRICT profile.
// Stage 2: O2-optimized IR vs. raw lifted IR, OPTIMIZED_RELAXED profile.
//          Only run when Stage 1 produces no failures.
struct FullPipelineResult
{
    std::optional<lifter::lift_stats_t> lift_stats; // populated on successful lift
    std::optional<visualization::CfgSnapshot> cfg;  // populated on successful lift
    bool lift_failed = false;
    std::string lift_error; // populated when lift_failed

    // Stage 1: raw lifted IR vs. native binary.
    std::optional<pipeline::PipelineReport> raw_vs_native;
    std::optional<pipeline::DeepDiveResult> raw_vs_native_dive;

    // Stage 2: O2 IR vs. raw lifted IR.  Nullopt when Stage 1 failed (N/A, not error).
    std::optional<pipeline::PipelineReport> opt_vs_raw;
    std::optional<pipeline::DeepDiveResult> opt_vs_raw_dive;

    // Non-empty when the O2 transform itself failed (unfold/fold error).
    // Treated as a Stage 2 error, not a Stage 1 failure.
    std::string opt_transform_error;

    // Stage 1 passed: lift succeeded and raw_vs_native has no failures.
    bool raw_pass() const;
    // Stage 2 passed: no transform error AND (no opt_vs_raw failures OR Stage 2 not run).
    // Returns true when Stage 2 was skipped because Stage 1 failed (N/A != failure).
    bool opt_pass() const;
    // Both stages passed.
    bool full_pass() const;
};

// ── Default fast pipeline (2-stage) ──────────────────────────────────────
//
// Stage 1 – wide discovery:  50 runs, full-range inputs,  bb=5000, loop=100
// Stage 2 – small inputs:   100 runs, max=0x10000 inputs, bb=2000, loop=50
//
// Checkpointing policy is profile-driven so raw/native validation can remain
// strict while optimized-vs-optimized comparisons can relax synchronization
// without changing stage structure.

enum class PipelineCheckpointProfile
{
    RAW_STRICT,
    OPTIMIZED_RELAXED,
};

// This is the canonical pipeline for all eval-suite + lifted-cli runs.
pipeline::PipelineSpec make_default_pipeline(
    const std::string &func_name,
    std::shared_ptr<verification::Executor> src,
    std::shared_ptr<verification::Executor> tgt,
    PipelineCheckpointProfile profile = PipelineCheckpointProfile::RAW_STRICT);

// Core: lift binary at entry_rva, run the default pipeline.
// deep_dive_count: 0 = skip deep-dive; >= 1 = deep-dive the first divergence found.
llvm::Expected<LiftAndVerifyResult>
lift_and_verify_named(llvm::LLVMContext &context,
                      const std::filesystem::path &path,
                      const std::string &func_name,
                      uint64_t entry_rva,
                      size_t deep_dive_count = 1,
                      std::string_view obfuscator = "");

// Full two-stage pipeline.
// Stage 1: raw lifted IR vs Unicorn, RAW_STRICT.
// Stage 2: O2-optimized IR vs raw lifted IR, OPTIMIZED_RELAXED.
//          Only run when Stage 1 produces no failures.
// deep_dive_count: 0 = skip deep-dives; >= 1 = deep-dive the first divergence per stage.
llvm::Expected<FullPipelineResult>
lift_and_verify_full_named(llvm::LLVMContext &context,
                           const std::filesystem::path &path,
                           const std::string &func_name,
                           uint64_t entry_rva,
                           size_t deep_dive_count = 1,
                           std::string_view obfuscator = "");
// Suite name -> compile-time CSV path.  Returns nullopt when the name is
// unknown (i.e. no compile definition was injected for it).
std::optional<std::filesystem::path> resolve_suite_name(const std::string &name);

// List all baked-in suite names (only those whose CSV macros were injected at
// compile time).
std::vector<std::string> known_suite_names();

// ── Mutation campaign ─────────────────────────────────────────────────────
//
// Result of a lift + mutation campaign run.
struct LiftAndMutateResult
{
    bool lift_failed = false;
    std::string lift_error;                                // populated when lift_failed or baseline fails
    std::optional<fault_injection::MutationReport> report; // populated on success
};

// Lift the function, run always_inline, check baseline, then run the full
// mutation campaign.  Returns a LiftAndMutateResult on success, or an
// llvm::Error if a fatal infrastructure failure occurred.
llvm::Expected<LiftAndMutateResult>
lift_and_mutate_named(llvm::LLVMContext &context,
                      const std::filesystem::path &path,
                      const std::string &func_name,
                      uint64_t entry_rva,
                      fault_injection::MutationCampaign::Config cfg = fault_injection::MutationCampaign::Config());
} // namespace lifted::eval
