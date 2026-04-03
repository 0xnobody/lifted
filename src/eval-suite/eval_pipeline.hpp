#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
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

enum class LiftStatus
{
    PASS,
    ERROR,
    TIMEOUT,
};

struct LiftAndVerifyResult
{
    std::optional<lifter::lift_stats_t> lift_stats;    // populated on successful lift
    std::optional<pipeline::PipelineReport> report;    // null only if lifting failed
    std::optional<pipeline::DeepDiveResult> deep_dive; // null if no divergence or skipped
    std::optional<visualization::CfgSnapshot> cfg;     // populated on successful lift
    LiftStatus lift_status = LiftStatus::PASS;
    std::string lift_message; // populated when lift_status != PASS

    bool lift_succeeded() const;
};

struct FullPipelineResult
{
    std::optional<lifter::lift_stats_t> lift_stats; // populated on successful lift
    std::optional<visualization::CfgSnapshot> cfg;  // populated on successful lift
    LiftStatus lift_status = LiftStatus::PASS;
    std::string lift_message; // populated when lift_status != PASS

    std::optional<pipeline::PipelineReport> raw_vs_native;
    std::optional<pipeline::DeepDiveResult> raw_vs_native_dive;

    std::optional<pipeline::PipelineReport> opt_vs_raw;
    std::optional<pipeline::DeepDiveResult> opt_vs_raw_dive;

    std::string opt_transform_error;

    bool lift_succeeded() const;
    bool raw_pass() const;
    bool opt_pass() const;
    bool full_pass() const;
};

enum class PhaseStatus
{
    NOT_RUN,
    PASS,
    FAIL,
    ERROR,
    SKIPPED,
};

struct VerificationPhaseResult
{
    PhaseStatus status = PhaseStatus::NOT_RUN;
    std::optional<pipeline::PipelineReport> report;
    std::optional<pipeline::DeepDiveResult> deep_dive;
    std::string error;
    std::string skip_reason;

    bool passed() const;
};

enum class MutationPhaseStatus
{
    NOT_REQUESTED,
    RUN,
    SKIPPED,
    ERROR,
};

enum class PipelineCheckpointProfile
{
    RAW_STRICT,
    OPTIMIZED_STRICT,
    OPTIMIZED_RELAXED,
};

struct MutationPhaseResult
{
    MutationPhaseStatus status = MutationPhaseStatus::NOT_REQUESTED;
    std::optional<fault_injection::MutationReport> report;
    std::string error;
    std::string skip_reason;

    bool executed() const;
};

struct Eg3ProfileResult
{
    PipelineCheckpointProfile profile;
    VerificationPhaseResult selftest;
    MutationPhaseResult mutation;

    explicit Eg3ProfileResult(
        PipelineCheckpointProfile checkpoint_profile =
            PipelineCheckpointProfile::OPTIMIZED_RELAXED)
        : profile(checkpoint_profile) {}
};

struct EvaluationRecord
{
    std::optional<lifter::lift_stats_t> lift_stats;
    std::optional<visualization::CfgSnapshot> cfg;
    LiftStatus lift_status = LiftStatus::PASS;
    std::string lift_message;

    VerificationPhaseResult raw_vs_native;
    VerificationPhaseResult opt_vs_raw;
    Eg3ProfileResult eg3_strict{PipelineCheckpointProfile::OPTIMIZED_STRICT};
    Eg3ProfileResult eg3_relaxed{PipelineCheckpointProfile::OPTIMIZED_RELAXED};

    bool lift_succeeded() const;
    size_t bbs_total() const;
};

struct EvaluationConfig
{
    size_t deep_dive_count = 1;
    std::string obfuscator;
    bool run_raw_vs_native = true;
    bool run_opt_vs_raw = true;
    bool run_eg3_strict = false;
    bool run_eg3_relaxed = false;
    bool run_mutation = false;
    PipelineCheckpointProfile raw_vs_native_profile = PipelineCheckpointProfile::RAW_STRICT;
    PipelineCheckpointProfile opt_vs_raw_profile = PipelineCheckpointProfile::OPTIMIZED_RELAXED;
    PipelineCheckpointProfile eg3_strict_profile = PipelineCheckpointProfile::OPTIMIZED_STRICT;
    PipelineCheckpointProfile eg3_relaxed_profile = PipelineCheckpointProfile::OPTIMIZED_RELAXED;
    fault_injection::MutationCampaignConfig mutation_config;
    uint64_t lift_timeout_sec = 0;
};

using LiftCompleteCallback = std::function<llvm::Error(const EvaluationRecord &)>;

pipeline::PipelineSpec make_default_pipeline(
    std::string_view phase_label,
    const std::string &func_name,
    std::shared_ptr<verification::Executor> src,
    std::shared_ptr<verification::Executor> tgt,
    PipelineCheckpointProfile profile = PipelineCheckpointProfile::RAW_STRICT);

llvm::Expected<LiftAndVerifyResult>
lift_and_verify_named(llvm::LLVMContext &context,
                      const std::filesystem::path &path,
                      const std::string &func_name,
                      uint64_t entry_rva,
                      size_t deep_dive_count = 1,
                      std::string_view obfuscator = "");

llvm::Expected<FullPipelineResult>
lift_and_verify_full_named(llvm::LLVMContext &context,
                           const std::filesystem::path &path,
                           const std::string &func_name,
                           uint64_t entry_rva,
                           size_t deep_dive_count = 1,
                           std::string_view obfuscator = "");

llvm::Expected<EvaluationRecord>
run_evaluation_named(llvm::LLVMContext &context,
                     const std::filesystem::path &path,
                     const std::string &func_name,
                     uint64_t entry_rva,
                     const EvaluationConfig &config = EvaluationConfig(),
                     LiftCompleteCallback on_lift_complete = {});

EvaluationRecord make_lift_status_record(const EvaluationConfig &config,
                                         LiftStatus status,
                                         std::string message);

llvm::Error write_evaluation_record_json(const EvaluationRecord &record,
                                         const std::filesystem::path &path);
llvm::Expected<EvaluationRecord> read_evaluation_record_json(const std::filesystem::path &path);

std::optional<std::filesystem::path> resolve_suite_name(const std::string &name);
std::vector<std::string> known_suite_names();

const char *lift_status_name(LiftStatus status);
const char *phase_status_name(PhaseStatus status);
const char *mutation_phase_status_name(MutationPhaseStatus status);
const char *pipeline_checkpoint_profile_name(PipelineCheckpointProfile profile);
} // namespace lifted::eval
