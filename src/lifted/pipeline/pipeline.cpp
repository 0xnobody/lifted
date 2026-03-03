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
        os << "    NEEDS_RERUN resolved: " << std::setw(3) << s.rerun_resolved
           << "  (" << pct(s.rerun_resolved, s.total_runs) << ")\n";

        if (!s.src_exit_types.empty())
            print_exit_counts(os, s.src_exit_types, "Src");
        if (!s.tgt_exit_types.empty())
            print_exit_counts(os, s.tgt_exit_types, "Tgt");

        os << "  Coverage:  " << s.cumulative_unique_blocks << " unique blocks\n";
        os << "  Corpus:    " << s.corpus_added << " entries added\n";

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
    std::shared_ptr<LIEF::Binary>  binary,
    uint64_t                       entry_rva,
    uint64_t                       run_index,
    std::unordered_set<uint64_t>  &accumulated_ext_calls)
{
    // Build run_params once.  It holds &cfg.oracle — cfg must outlive this call.
    auto run_params = cfg.to_run_params(binary, entry_rva);

    // ── src run (no prev_record) ──────────────────────────────────────────────
    auto src_verif  = cfg.to_verif_params(nullptr);
    auto src_result = src.run_single(run_params, src_verif);
    if (!src_result)
        return src_result.takeError();

    // ── update accumulated ext calls and inform tgt ───────────────────────────
    for (uint64_t addr : src_result->ext_calls)
        accumulated_ext_calls.insert(addr);
    tgt.hint_external_rvas(accumulated_ext_calls);

    // ── tgt run (prev_record = src's checkpoint record) ───────────────────────
    auto tgt_verif  = cfg.to_verif_params(&src_result->checkpoint_record);
    auto tgt_result = tgt.run_single(run_params, tgt_verif);
    if (!tgt_result)
        return tgt_result.takeError();

    // ── compare ───────────────────────────────────────────────────────────────
    auto cmp = verification::compare_runs(*src_result, *tgt_result, spec_.compare_cfg);

    bool was_rerun          = false;
    bool was_rerun_resolved = false;

    // ── NEEDS_RERUN: re-run src with tgt's checkpoint record ──────────────────
    // The plan's directionality: src ran further → re-run src constrained to
    // tgt's depth so both terminate at the same checkpoint index.
    if (cmp.status == verification::comparison_status::NEEDS_RERUN)
    {
        was_rerun = true;

        auto src_verif2 = cfg.to_verif_params(&tgt_result->checkpoint_record);
        auto src_result2 = src.run_single(run_params, src_verif2);
        if (!src_result2)
            return src_result2.takeError();

        *src_result = std::move(*src_result2);
        cmp = verification::compare_runs(*src_result, *tgt_result, spec_.compare_cfg);
        was_rerun_resolved = (cmp.status == verification::comparison_status::PASS);
    }

    // ── diff if diverged ──────────────────────────────────────────────────────
    std::optional<verification::diff_result_t> diff;
    if (cmp.status == verification::comparison_status::FAIL_DIVERGED)
        diff = verification::diff_runs(*src_result, *tgt_result, spec_.compare_cfg);

    return RunOutcome{
        .run_index          = run_index,
        .config             = cfg,
        .src_result         = std::move(*src_result),
        .tgt_result         = std::move(*tgt_result),
        .comparison         = cmp,
        .diff               = std::move(diff),
        .was_rerun          = was_rerun,
        .was_rerun_resolved = was_rerun_resolved,
    };
}

llvm::Expected<PipelineReport> Pipeline::run(
    std::shared_ptr<LIEF::Binary> binary,
    uint64_t                       entry_rva)
{
    // ── Construct executors once (reused across all stages + runs) ────────────
    auto src_exp = spec_.executors.make_src();
    if (!src_exp)
        return src_exp.takeError();
    auto &src = **src_exp;

    auto tgt_exp = spec_.executors.make_tgt();
    if (!tgt_exp)
        return tgt_exp.takeError();
    auto &tgt = **tgt_exp;

    // ── Shared state across all stages ────────────────────────────────────────
    std::unordered_set<uint64_t> accumulated_ext_calls;
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

        for (uint64_t run_idx = 0; run_idx < configs.size(); ++run_idx)
        {
            const RunConfig &cfg = configs[run_idx];

            auto outcome_exp = execute_one(
                src, tgt, cfg, binary, entry_rva, run_idx, accumulated_ext_calls);

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

            if (outcome.was_rerun_resolved)
                ++stage_report.rerun_resolved;

            // Build corpus entry from src's trace.
            CorpusEntry entry{
                .config      = cfg,
                .exit_reason = outcome.src_result.exit_reason,
                .bb_trace    = outcome.src_result.bb_trace,
                .run_index   = run_idx,
            };
            current_corpus.add_if_interesting(std::move(entry), spec_.classifier);
        }

        stage_report.corpus_added             = current_corpus.size() - corpus_before;
        stage_report.cumulative_unique_blocks = current_corpus.unique_blocks_covered();
        report.stages.push_back(std::move(stage_report));
    }

    report.final_corpus = std::move(current_corpus);
    return report;
}

} // namespace lifted::pipeline
