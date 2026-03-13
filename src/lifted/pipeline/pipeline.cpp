#include "pipeline.hpp"

#include "../verification/comparator.hpp"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace lifted::pipeline {

// ── helpers ───────────────────────────────────────────────────────────────────

namespace
{

const char *exit_type_name(verification::exit_type t)
{
    using ET = verification::exit_type;
    switch (t)
    {
    case ET::NATURAL_EXIT:            return "NATURAL_EXIT";
    case ET::EXCEPTION:               return "EXCEPTION";
    case ET::MISSING_BLOCK:           return "MISSING_BLOCK";
    case ET::CHECKPOINT_MISMATCH:     return "CHECKPOINT_MISMATCH";
    case ET::LAST_CHECKPOINT_REACHED: return "LAST_CHECKPOINT_REACHED";
    case ET::LOOP_LIMIT:              return "LOOP_LIMIT";
    case ET::BB_LIMIT:                return "BB_LIMIT";
    }
    return "UNKNOWN";
}

std::string pct(size_t num, size_t denom)
{
    if (denom == 0)
        return "N/A";
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1)
       << (100.0 * static_cast<double>(num) / static_cast<double>(denom)) << "%";
    return ss.str();
}

void print_exit_counts(std::ostream &os, const ExitTypeCounts &counts, const char *label)
{
    os << "  " << label << " exit types:";
    for (const auto &[et, n] : counts)
        os << "  " << exit_type_name(et) << "=" << n;
    os << "\n";
}

} // anonymous namespace

// ── PipelineReport ────────────────────────────────────────────────────────────

size_t PipelineReport::total_runs() const
{
    size_t n = 0;
    for (const auto &s : stages)
        n += s.total_runs;
    return n;
}

size_t PipelineReport::total_failures() const
{
    size_t n = 0;
    for (const auto &s : stages)
        n += s.fail_count;
    return n;
}

static std::string fmt_ns(std::chrono::nanoseconds ns, size_t count)
{
    double total_ms  = static_cast<double>(ns.count()) / 1e6;
    double avg_ms    = (count > 0) ? (total_ms / static_cast<double>(count)) : 0.0;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%8.1f ms total,  %6.2f ms/run avg", total_ms, avg_ms);
    return buf;
}

void PipelineReport::print(std::ostream &os) const
{
    os << "\n=== Pipeline: " << pipeline_name << " ===\n";

    for (size_t si = 0; si < stages.size(); ++si)
    {
        const StageReport &s = stages[si];
        os << "\n[Stage " << (si + 1) << "] " << s.stage_name << "\n";
        os << "  Comparison outcomes:\n";

        os << "    PASS:               " << std::setw(5) << s.pass_count
           << "  (" << pct(s.pass_count, s.total_runs) << ")\n";
        os << "    FAIL_DIVERGED:      " << std::setw(5) << s.fail_count
           << "  (" << pct(s.fail_count, s.total_runs) << ")\n";
        os << "    FAIL_INCOMPARABLE:  " << std::setw(5) << s.incomparable
           << "  (" << pct(s.incomparable, s.total_runs) << ")\n";
        os << "    NEEDS_RERUN triggered: " << std::setw(3) << s.reruns_triggered
           << "  (" << pct(s.reruns_triggered, s.total_runs) << ")\n";
        os << "    NEEDS_RERUN → PASS:    " << std::setw(3) << s.rerun_resolved
           << "  (" << pct(s.rerun_resolved, s.total_runs) << ")\n";

        if (!s.src_exit_types.empty())
            print_exit_counts(os, s.src_exit_types, "Src (final)");
        if (s.reruns_triggered > 0 && s.src_initial_exit_types != s.src_exit_types)
            print_exit_counts(os, s.src_initial_exit_types, "Src (initial)");
        if (!s.tgt_exit_types.empty())
            print_exit_counts(os, s.tgt_exit_types, "Tgt");

        os << "  Coverage:  " << s.cumulative_unique_blocks << " unique blocks\n";
        os << "  Corpus:    " << s.corpus_added << " entries added\n";
        os << "  Timing (wall clock, executor run_single only):\n";
        os << "    Src: " << fmt_ns(s.src_wall_ns, s.total_runs) << "\n";
        os << "    Tgt: " << fmt_ns(s.tgt_wall_ns, s.total_runs) << "\n";

        if (!s.divergences.empty())
        {
            os << "\n  DIVERGENCES (" << s.divergences.size() << "):\n";
            for (const auto &outcome : s.divergences)
            {
                char seed_buf[32];
                std::snprintf(seed_buf, sizeof(seed_buf), "0x%llx",
                              static_cast<unsigned long long>(outcome.config.seed));

                os << "    Run #" << outcome.run_index << "  seed=" << seed_buf << "\n";
                os << "      Src exit: "
                   << exit_type_name(outcome.src_result.exit_reason)
                   << "   Tgt exit: "
                   << exit_type_name(outcome.tgt_result.exit_reason)
                   << "\n";

                if (outcome.diff)
                    outcome.diff->print(os);
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    size_t runs  = total_runs();
    size_t fails = total_failures();
    size_t passes = 0;
    for (const auto &s : stages)
        passes += s.pass_count;

    os << "\n=== Summary ===\n";
    os << "Total runs:   " << runs << "\n";
    os << "PASS:         " << passes
       << "  (" << pct(passes, runs) << ")"
       << "   [includes rerun-resolved]\n";
    os << "FAIL:         " << fails
       << "  (" << pct(fails, runs) << ")\n";
    os << "Unique BBs:   " << final_corpus.unique_blocks_covered() << "\n";
    os << "Corpus:       " << final_corpus.size() << " entries\n";

    // Aggregate timing across all stages.
    std::chrono::nanoseconds total_src_ns{0}, total_tgt_ns{0};
    for (const auto &s : stages)
    {
        total_src_ns += s.src_wall_ns;
        total_tgt_ns += s.tgt_wall_ns;
    }
    os << "Timing (totals across all stages):\n";
    os << "  Src: " << fmt_ns(total_src_ns, runs) << "\n";
    os << "  Tgt: " << fmt_ns(total_tgt_ns, runs) << "\n";
}

// ── Pipeline ─────────────────────────────────────────────────────────────────

Pipeline::Pipeline(PipelineSpec spec)
    : spec_(std::move(spec))
{
}

llvm::Expected<RunOutcome> Pipeline::execute_one(
    verification::Executor        &src,
    verification::Executor        &tgt,
    const RunConfig               &cfg,
    const lifted::BinaryContext   &bin_ctx,
    uint64_t                       entry_rva,
    uint64_t                       run_index)
{
    using Clock = std::chrono::steady_clock;

    // Build run_params once.  It holds &cfg.oracle — cfg must outlive this call.
    auto run_params = cfg.to_run_params(bin_ctx, entry_rva);

    // ── src run (no prev_record) ──────────────────────────────────────────
    auto src_verif  = cfg.to_verif_params(nullptr);
    auto t_src0     = Clock::now();
    auto src_result = src.run_single(run_params, src_verif);
    std::chrono::nanoseconds src_wall_ns = Clock::now() - t_src0;
    if (!src_result)
        return src_result.takeError();

    // ── tgt run (prev_record = src's checkpoint record) ─────────────────────
    auto tgt_verif  = cfg.to_verif_params(&src_result->checkpoint_record);
    auto t_tgt0     = Clock::now();
    auto tgt_result = tgt.run_single(run_params, tgt_verif);
    std::chrono::nanoseconds tgt_wall_ns = Clock::now() - t_tgt0;
    if (!tgt_result)
        return tgt_result.takeError();

    // ── compare ─────────────────────────────────────────────────────────────────────────
    auto compare_cfg = spec_.compare_cfg;
    compare_cfg.dimensions = cfg.compare_dims;
    auto cmp = verification::compare_runs(*src_result, *tgt_result, compare_cfg);

    const auto initial_src_exit  = src_result->exit_reason;  // save before any rerun overwrites
    bool was_rerun               = false;
    bool was_rerun_resolved      = false;

    // ── NEEDS_RERUN: re-run src with tgt's checkpoint record ────────────────────
    // The plan's directionality: src ran further → re-run src constrained to
    // tgt's depth so both terminate at the same checkpoint index.
    if (cmp.status == verification::comparison_status::NEEDS_RERUN)
    {
        was_rerun = true;

        auto src_verif2  = cfg.to_verif_params(&tgt_result->checkpoint_record);
        auto t_src_rerun = Clock::now();
        auto src_result2 = src.run_single(run_params, src_verif2);
        src_wall_ns     += Clock::now() - t_src_rerun;
        if (!src_result2)
            return src_result2.takeError();

        *src_result = std::move(*src_result2);
        cmp = verification::compare_runs(*src_result, *tgt_result, compare_cfg);
        was_rerun_resolved = (cmp.status == verification::comparison_status::PASS);
    }

    // ── diff if diverged ──────────────────────────────────────────────────────────────────────────
    std::optional<verification::diff_result_t> diff;
    if (cmp.status == verification::comparison_status::FAIL_DIVERGED)
        diff = verification::diff_runs(*src_result, *tgt_result, compare_cfg);

    return RunOutcome{
        .run_index               = run_index,
        .config                  = cfg,
        .src_result              = std::move(*src_result),
        .tgt_result              = std::move(*tgt_result),
        .comparison              = cmp,
        .diff                    = std::move(diff),
        .initial_src_exit_reason = initial_src_exit,
        .was_rerun               = was_rerun,
        .was_rerun_resolved      = was_rerun_resolved,
        .src_wall_ns             = src_wall_ns,
        .tgt_wall_ns             = tgt_wall_ns,
    };
}

llvm::Expected<PipelineReport> Pipeline::run(
    const lifted::BinaryContext   &bin_ctx,
    uint64_t                       entry_rva)
{
    // ── Assign executors (shared, created eagerly by caller) ────────────────
    src_executor_ = spec_.executors.src;
    tgt_executor_ = spec_.executors.tgt;
    if (!src_executor_ || !tgt_executor_)
        return llvm::make_error<llvm::StringError>(
            "Pipeline::run(): src and tgt executors must be non-null",
            llvm::inconvertibleErrorCode());
    auto &src = *src_executor_;
    auto &tgt = *tgt_executor_;

    // ── Shared state across all stages ────────────────────────────────────────
    Corpus             current_corpus;

    PipelineReport report;
    report.pipeline_name = spec_.name;

    for (auto &stage : spec_.stages)
    {
        auto configs      = stage->generate_configs(current_corpus);
        size_t corpus_before = current_corpus.size();

        StageReport stage_report;
        stage_report.stage_name = stage->name();
        stage_report.total_runs = configs.size();

        if (llvm::errs().is_displayed())
            llvm::errs() << "[" << stage->name() << "] ";

        for (uint64_t run_idx = 0; run_idx < configs.size(); ++run_idx)
        {
            const RunConfig &cfg = configs[run_idx];

            auto outcome_exp = execute_one(
                src, tgt, cfg, bin_ctx, entry_rva, run_idx);

            if (!outcome_exp)
            {
                // Surface executor errors (JIT linking failures, Unicorn faults, …).
                // Count as FAIL_INCOMPARABLE rather than aborting the whole pipeline.
                llvm::errs() << "execute_one error at run " << run_idx << ": "
                             << llvm::toString(outcome_exp.takeError()) << "\n";
                ++stage_report.incomparable;
                continue;
            }

            RunOutcome &outcome = *outcome_exp;

            // Accumulate exit type distributions.
            ++stage_report.src_exit_types[outcome.src_result.exit_reason];
            ++stage_report.src_initial_exit_types[outcome.initial_src_exit_reason];
            ++stage_report.tgt_exit_types[outcome.tgt_result.exit_reason];

            // Update comparison counters.
            using CS = verification::comparison_status;
            switch (outcome.comparison.status)
            {
            case CS::PASS:
                ++stage_report.pass_count;
                break;
            case CS::FAIL_DIVERGED:
                ++stage_report.fail_count;
                stage_report.divergences.push_back(outcome);
                break;
            case CS::FAIL_INCOMPARABLE:
                ++stage_report.incomparable;
                break;
            case CS::NEEDS_RERUN:
                // Should not happen: execute_one always resolves NEEDS_RERUN.
                ++stage_report.incomparable;
                break;
            }

            if (outcome.was_rerun)
                ++stage_report.reruns_triggered;
            if (outcome.was_rerun_resolved)
                ++stage_report.rerun_resolved;

            stage_report.src_wall_ns += outcome.src_wall_ns;
            stage_report.tgt_wall_ns += outcome.tgt_wall_ns;

            // Accumulate block hit counts for visualization.
            for (uint64_t rva : outcome.src_result.bb_trace)
                ++report.src_block_hits[rva];

            // Build corpus entry from src's trace.
            CorpusEntry entry{
                .config      = cfg,
                .exit_reason = outcome.src_result.exit_reason,
                .bb_trace    = outcome.src_result.bb_trace,
                .run_index   = run_idx,
            };
            current_corpus.add_if_interesting(std::move(entry), spec_.classifier);
            if (llvm::errs().is_displayed() && (run_idx + 1) % 10 == 0)
                llvm::errs() << '.';
        }

        if (llvm::errs().is_displayed())
            llvm::errs() << '\n';

        stage_report.corpus_added             = current_corpus.size() - corpus_before;
        stage_report.cumulative_unique_blocks = current_corpus.unique_blocks_covered();
        report.stages.push_back(std::move(stage_report));
    }

    report.final_corpus = std::move(current_corpus);
    return report;
}

} // namespace lifted::pipeline
