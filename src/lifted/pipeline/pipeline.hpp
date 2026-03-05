#pragma once

#include "corpus.hpp"
#include "deep_dive.hpp"
#include "run_config.hpp"
#include "stage.hpp"

#include "../verification/comparator.hpp"
#include "../verification/executor.hpp"

#include "compat/lief_compat.hpp"

#include <llvm/Support/Error.h>

#include <chrono>
#include <cstdint>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <unordered_set>
#include <string>
#include <vector>

namespace lifted::pipeline {

// ── ExecutorPair ──────────────────────────────────────────────────────────────
// Executors are created eagerly by the caller and shared across pipelines.

struct ExecutorPair
{
    std::shared_ptr<verification::Executor> src;
    std::shared_ptr<verification::Executor> tgt;
};

// ── ExitTypeCounts ────────────────────────────────────────────────────────────

using ExitTypeCounts = std::map<verification::exit_type, size_t>;

// ── RunOutcome ────────────────────────────────────────────────────────────────

struct RunOutcome
{
    uint64_t                              run_index;
    RunConfig                             config;
    verification::run_result_t            src_result;
    verification::run_result_t            tgt_result;
    verification::comparison_result_t     comparison;
    std::optional<verification::diff_result_t> diff;  // set iff FAIL_DIVERGED

    /// Exit type of src on its INITIAL run (before any NEEDS_RERUN rerun).
    /// Equals src_result.exit_reason when was_rerun is false.
    verification::exit_type initial_src_exit_reason = verification::exit_type::NATURAL_EXIT;

    /// True iff a NEEDS_RERUN was observed and resolved (to any outcome).
    bool was_rerun = false;
    /// True iff the rerun above resolved to PASS.
    bool was_rerun_resolved = false;

    /// Wall-clock time spent inside run_single for each side (including reruns).
    std::chrono::nanoseconds src_wall_ns{0};
    std::chrono::nanoseconds tgt_wall_ns{0};
};

// ── StageReport ───────────────────────────────────────────────────────────────

struct StageReport
{
    std::string stage_name;
    size_t      total_runs     = 0;
    size_t      pass_count     = 0;  // comparison_status::PASS (includes rerun-resolved)
    size_t      fail_count     = 0;  // comparison_status::FAIL_DIVERGED
    size_t      incomparable      = 0;  // comparison_status::FAIL_INCOMPARABLE
    size_t      reruns_triggered  = 0;  // runs where NEEDS_RERUN was observed (regardless of outcome)
    size_t      rerun_resolved    = 0;  // subset of reruns_triggered that resolved to PASS
    size_t      corpus_added   = 0;  // entries added to corpus by this stage

    ExitTypeCounts src_exit_types;          // final (post-rerun) src exit types
    ExitTypeCounts src_initial_exit_types;  // initial src exit types (pre-rerun); same as src_exit_types when reruns_triggered == 0
    ExitTypeCounts tgt_exit_types;

    /// Accumulated wall-clock time spent inside run_single for each executor.
    std::chrono::nanoseconds src_wall_ns{0};
    std::chrono::nanoseconds tgt_wall_ns{0};

    /// All FAIL_DIVERGED outcomes — full RunOutcome retained for post-analysis.
    std::vector<RunOutcome> divergences;

    /// Unique basic blocks covered by corpus entries up to and including this stage.
    size_t cumulative_unique_blocks = 0;
};

// ── PipelineReport ────────────────────────────────────────────────────────────

struct PipelineReport
{
    std::string              pipeline_name;
    std::vector<StageReport> stages;
    Corpus                   final_corpus;

    size_t total_runs()     const;
    size_t total_failures() const;
    void   print(std::ostream &os) const;
};

// ── PipelineSpec ──────────────────────────────────────────────────────────────

struct PipelineSpec
{
    std::string                               name;
    ExecutorPair                              executors;
    std::vector<std::unique_ptr<PipelineStage>> stages;
    corpus_classifier_t                       classifier  = make_combined_classifier();
    verification::compare_config_t            compare_cfg = {};
};

// ── Pipeline ─────────────────────────────────────────────────────────────────

class Pipeline
{
public:
    explicit Pipeline(PipelineSpec spec);

    llvm::Expected<PipelineReport> run(
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_rva);

    /// Re-run a diverging outcome with full event-detail recording to produce a
    /// side-by-side chronological trace display.  Requires run() to have been
    /// called first (executors are reused).
    llvm::Expected<DeepDiveResult> deep_dive(
        const RunOutcome              &outcome,
        std::shared_ptr<LIEF::Binary>  binary,
        uint64_t                       entry_rva,
        const DeepDiveConfig          &cfg = {});

private:
    PipelineSpec spec_;
    std::shared_ptr<verification::Executor> src_executor_;
    std::shared_ptr<verification::Executor> tgt_executor_;

    /// Execute one (src, tgt) pair for the given config.
    /// Handles the fixed directionality (src first, then tgt with src's record),
    /// NEEDS_RERUN resolution, and optional diff on FAIL_DIVERGED.
    ///
    /// accumulated_ext_calls is updated in-place from src's ext_calls and
    /// forwarded to tgt via hint_external_rvas before each tgt run.
    llvm::Expected<RunOutcome> execute_one(
        verification::Executor   &src,
        verification::Executor   &tgt,
        const RunConfig          &cfg,
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t                  entry_rva,
        uint64_t                  run_index,
        std::unordered_set<uint64_t> &accumulated_ext_calls);
};

} // namespace lifted::pipeline
