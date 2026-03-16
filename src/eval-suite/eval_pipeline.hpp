#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>

#include "pipeline/pipeline.hpp"
#include "pipeline/deep_dive.hpp"
#include "visualization/cfg_data.hpp"
#include "lifter/lifter_types.hpp"

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

    // ── Default fast pipeline (3-stage) ──────────────────────────────────────
    //
    // Stage 1 – wide discovery:  50 runs, full-range inputs,  bb=5000, loop=100
    // Stage 2 – small inputs:   100 runs, max=0x10000 inputs, bb=2000, loop=50
    // Stage 3 – corpus replay:   replay interesting entries + 30 medium seeds, bb=3000, loop=75
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

    // Suite name -> compile-time CSV path.  Returns nullopt when the name is
    // unknown (i.e. no compile definition was injected for it).
    std::optional<std::filesystem::path> resolve_suite_name(const std::string &name);

    // List all baked-in suite names (only those whose CSV macros were injected at
    // compile time).
    std::vector<std::string> known_suite_names();

} // namespace lifted::eval
