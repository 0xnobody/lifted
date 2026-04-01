#include "campaign_reporting.hpp"

#include "visualization/cfg_dot.hpp"
#include "visualization/pipeline_overlay.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <ostream>

#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

namespace fs = std::filesystem;

namespace lifted::eval
{
namespace
{
double coverage_pct(const pipeline::PipelineReport &report, size_t bbs_total)
{
    if (bbs_total == 0 || report.stages.empty())
        return 0.0;
    return 100.0 * static_cast<double>(report.stages.back().cumulative_unique_blocks) /
           static_cast<double>(bbs_total);
}

std::pair<double, double> pipeline_executor_ms(const pipeline::PipelineReport &r)
{
    double src = 0.0;
    double tgt = 0.0;
    for (const auto &stg : r.stages)
    {
        src += static_cast<double>(stg.src_wall_ns.count()) * 1e-6;
        tgt += static_cast<double>(stg.tgt_wall_ns.count()) * 1e-6;
    }
    return {src, tgt};
}

std::string fmt_dbl(double v, int precision = 1)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%.*f", precision, v);
    return buf;
}

template <typename Summary>
void write_summary_artifacts_impl(const Summary &summary,
                                  const std::string &suite_label,
                                  const fs::path &out_dir)
{
    const fs::path rpt_path = out_dir / "report.txt";
    std::ofstream rpt(rpt_path);
    if (rpt)
        summary.print_summary(suite_label, rpt);
    else
        llvm::errs() << "warning: cannot write '" << rpt_path.string() << "'\n";

    summary.write_csv(out_dir / "summary.csv");
}
} // namespace

void RunSummary::record(const std::string &label,
                        const FullPipelineResult &r,
                        std::string_view binary,
                        std::string_view func,
                        std::string_view obfusc)
{
    size_t bbs = r.lift_stats ? r.lift_stats->bbs_total : 0;
    if (!r.lift_failed && r.lift_stats)
    {
        total_lift_ms += r.lift_stats->total_time_ms;
        ++lift_count;
    }
    CsvRow row;
    row.binary = std::string(binary);
    row.func = std::string(func);
    row.obfuscator = std::string(obfusc);
    row.bbs_total = bbs;

    if (r.lift_failed)
    {
        ++stage1.tested;
        ++stage1.errors;
        stage1.failing.push_back(label + " [lift error]");
        lift_errors.push_back(label + ": " + r.lift_error);
        row.stage1_result = "LIFT_FAIL";
        row.stage2_result = "N/A";
        csv_rows.push_back(std::move(row));
        return;
    }

    ++stage1.tested;
    if (r.raw_vs_native && r.raw_vs_native->total_failures() > 0)
    {
        ++stage1.fail;
        stage1.failing.push_back(label);
        row.stage1_result = "FAIL";
    }
    else if (r.raw_vs_native)
    {
        ++stage1.pass;
        row.stage1_result = "PASS";
    }
    else
    {
        ++stage1.errors;
        stage1.failing.push_back(label + " [pipeline error]");
        row.stage1_result = "ERROR";
    }
    if (r.raw_vs_native)
        row.stage1_coverage_pct = coverage_pct(*r.raw_vs_native, bbs);
    if (row.stage1_result == "PASS")
    {
        stage1.total_coverage_pct += row.stage1_coverage_pct;
        ++stage1.pass_cov_count;
    }
    if (r.raw_vs_native)
    {
        auto [s, t] = pipeline_executor_ms(*r.raw_vs_native);
        stage1.total_src_wall_ms += s;
        stage1.total_tgt_wall_ms += t;
    }

    if (!r.opt_transform_error.empty())
    {
        ++stage2.tested;
        ++stage2.errors;
        stage2.failing.push_back(label + " [transform error]");
        row.stage2_result = "ERROR";
    }
    else if (r.opt_vs_raw)
    {
        ++stage2.tested;
        if (r.opt_vs_raw->total_failures() > 0)
        {
            ++stage2.fail;
            stage2.failing.push_back(label);
            row.stage2_result = "FAIL";
        }
        else
        {
            ++stage2.pass;
            row.stage2_result = "PASS";
        }
        row.stage2_coverage_pct = coverage_pct(*r.opt_vs_raw, bbs);
        if (row.stage2_result == "PASS")
        {
            stage2.total_coverage_pct += row.stage2_coverage_pct;
            ++stage2.pass_cov_count;
        }
        auto [s2s, s2t] = pipeline_executor_ms(*r.opt_vs_raw);
        stage2.total_src_wall_ms += s2s;
        stage2.total_tgt_wall_ms += s2t;
    }
    else
    {
        row.stage2_result = "N/A";
    }

    csv_rows.push_back(std::move(row));
}

void RunSummary::record_fatal(const std::string &label,
                              std::string_view binary,
                              std::string_view func,
                              std::string_view obfusc)
{
    ++stage1.tested;
    ++stage1.errors;
    stage1.failing.push_back(label + " [fatal]");
    CsvRow row;
    row.binary = std::string(binary);
    row.func = std::string(func);
    row.obfuscator = std::string(obfusc);
    row.stage1_result = "ERROR";
    row.stage2_result = "N/A";
    csv_rows.push_back(std::move(row));
}

int RunSummary::exit_code() const
{
    if (stage1.tested == 0 && stage1.errors > 0)
        return 2;
    if (stage1.fail > 0 || stage2.fail > 0)
        return 1;
    return 0;
}

void RunSummary::print_summary(const std::string &suite_label, std::ostream &os) const
{
    auto pct = [](size_t n, size_t total) -> double
    {
        return total > 0 ? 100.0 * static_cast<double>(n) / static_cast<double>(total) : 0.0;
    };

    os << "\n=== EVALUATION REPORT: " << suite_label << " ===\n";

    os << "\n--- Stage 1: Raw Lifted IR vs. Native Binary ---\n";
    os << "  Functions tested:  " << stage1.tested << "\n";
    os << "  PASS:    " << stage1.pass << "  (" << fmt_dbl(pct(stage1.pass, stage1.tested)) << "%)\n";
    os << "  FAIL:    " << stage1.fail << "  (" << fmt_dbl(pct(stage1.fail, stage1.tested)) << "%)\n";
    os << "  ERRORS:  " << stage1.errors << "\n";
    double s1_avg = stage1.pass_cov_count > 0
        ? stage1.total_coverage_pct / static_cast<double>(stage1.pass_cov_count) : 0.0;
    os << "  Avg. coverage (PASS only):  " << fmt_dbl(s1_avg) << "%\n";
    double lift_avg = lift_count > 0 ? total_lift_ms / static_cast<double>(lift_count) : 0.0;
    double s1_src_avg = stage1.tested > 0
        ? stage1.total_src_wall_ms / static_cast<double>(stage1.tested) : 0.0;
    double s1_tgt_avg = stage1.tested > 0
        ? stage1.total_tgt_wall_ms / static_cast<double>(stage1.tested) : 0.0;
    os << "  Avg. lift time:             " << fmt_dbl(lift_avg, 2) << " ms\n";
    os << "  Avg. pipeline run (src):    " << fmt_dbl(s1_src_avg, 2) << " ms\n";
    os << "  Avg. pipeline run (tgt):    " << fmt_dbl(s1_tgt_avg, 2) << " ms\n";
    os << "  Avg. pipeline run (total):  " << fmt_dbl(s1_src_avg + s1_tgt_avg, 2) << " ms\n";
    if (!stage1.failing.empty())
    {
        os << "  Failures:";
        for (const auto &f : stage1.failing)
            os << " " << f;
        os << "\n";
    }

    os << "\n--- Stage 2: O2-Optimized IR vs. Raw Lifted IR ---\n";
    os << "  Functions tested (Stage 1 PASS only):  " << stage2.tested << "\n";
    os << "  PASS:    " << stage2.pass << "  (" << fmt_dbl(pct(stage2.pass, stage2.tested)) << "%)\n";
    os << "  FAIL:    " << stage2.fail << "  (" << fmt_dbl(pct(stage2.fail, stage2.tested)) << "%)\n";
    os << "  ERRORS:  " << stage2.errors << "\n";
    double s2_avg = stage2.pass_cov_count > 0
        ? stage2.total_coverage_pct / static_cast<double>(stage2.pass_cov_count) : 0.0;
    os << "  Avg. coverage (PASS only):  " << fmt_dbl(s2_avg) << "%\n";
    double s2_src_avg = stage2.tested > 0
        ? stage2.total_src_wall_ms / static_cast<double>(stage2.tested) : 0.0;
    double s2_tgt_avg = stage2.tested > 0
        ? stage2.total_tgt_wall_ms / static_cast<double>(stage2.tested) : 0.0;
    os << "  Avg. pipeline run (src):    " << fmt_dbl(s2_src_avg, 2) << " ms\n";
    os << "  Avg. pipeline run (tgt):    " << fmt_dbl(s2_tgt_avg, 2) << " ms\n";
    os << "  Avg. pipeline run (total):  " << fmt_dbl(s2_src_avg + s2_tgt_avg, 2) << " ms\n";
    if (!stage2.failing.empty())
    {
        os << "  Failures:";
        for (const auto &f : stage2.failing)
            os << " " << f;
        os << "\n";
    }

    size_t full_pass = 0;
    size_t s1_no_s2 = 0;
    size_t s2_na_fail = 0;
    for (const auto &row : csv_rows)
    {
        if (row.stage1_result == "PASS" && row.stage2_result == "PASS")
            ++full_pass;
        else if (row.stage1_result == "PASS" && row.stage2_result == "N/A")
            ++s1_no_s2;
        else if (row.stage2_result == "N/A" && row.stage1_result != "PASS")
            ++s2_na_fail;
    }
    os << "\n--- Combined ---\n";
    os << "  Full PASS (both stages):  " << full_pass
       << "  (" << fmt_dbl(pct(full_pass, stage1.tested)) << "%)\n";
    if (s1_no_s2 > 0)
        os << "  Stage 1 only PASS (--no-full-pipeline):  " << s1_no_s2 << "\n";
    os << "  Stage 2 N/A (Stage 1 failed):  " << s2_na_fail << "\n";

    const char *status = exit_code() == 0 ? "PASS" : (exit_code() == 1 ? "FAIL" : "ERROR");
    os << "\nExit status: " << status << "\n";
}

void RunSummary::write_csv(const fs::path &path) const
{
    std::ofstream f(path);
    if (!f)
    {
        llvm::errs() << "warning: cannot write CSV to '" << path.string() << "'\n";
        return;
    }
    f << "binary,func,obfuscator,bbs_total,"
         "stage1_result,stage1_coverage_pct,"
         "stage2_result,stage2_coverage_pct\n";
    for (const auto &row : csv_rows)
    {
        f << row.binary << "," << row.func << "," << row.obfuscator << ","
          << row.bbs_total << ","
          << row.stage1_result << "," << fmt_dbl(row.stage1_coverage_pct) << ","
          << row.stage2_result << "," << fmt_dbl(row.stage2_coverage_pct) << "\n";
    }
}


void write_summary_artifacts(const RunSummary &summary,
                             const std::string &suite_label,
                             const fs::path &out_dir)
{
    write_summary_artifacts_impl(summary, suite_label, out_dir);
}


void write_function_dot(const FullPipelineResult &r,
                        const fs::path &out_dir,
                        const std::string &stem,
                        const std::string &func,
                        const std::string &render_fmt)
{
    if (!r.cfg)
        return;

    visualization::CfgDotOptions cfg_opts;
    cfg_opts.graph_title = stem + "::" + func;
    std::string dot;

    if (r.raw_vs_native)
    {
        visualization::OverlayData od;
        od.block_hits = &r.raw_vs_native->src_block_hits;
        for (const auto &stg : r.raw_vs_native->stages)
        {
            if (!stg.divergences.empty())
            {
                od.divergence = &stg.divergences[0];
                break;
            }
        }
        visualization::OverlayOptions oo;
        oo.cfg_opts = cfg_opts;
        dot = visualization::overlay_to_dot(*r.cfg, od, oo);
    }
    else
    {
        dot = visualization::cfg_to_dot(*r.cfg, cfg_opts);
    }

    fs::path dot_path = out_dir / (stem + "_" + func + ".dot");
    {
        std::error_code ec;
        llvm::raw_fd_ostream os(dot_path.string(), ec);
        if (ec)
        {
            llvm::errs() << "  [WARN] cannot write DOT '" << dot_path.string() << "': "
                         << ec.message() << "\n";
            return;
        }
        os << dot;
    }

    if (!render_fmt.empty())
    {
        fs::path rendered = fs::path(dot_path).replace_extension("." + render_fmt);
        std::string cmd = "dot -T" + render_fmt + " -o " + rendered.string() + " " + dot_path.string();
        if (std::system(cmd.c_str()) != 0)
            llvm::errs() << "  [WARN] graphviz render failed for " << dot_path.string() << "\n";
    }
}

void write_function_reports(const FullPipelineResult &r,
                            const fs::path &out_dir,
                            const std::string &stem,
                            const std::string &func)
{
    const std::string prefix = stem + "_" + func;

    {
        std::ofstream f(out_dir / (prefix + ".lift.report.txt"));
        if (r.lift_failed)
        {
            f << "[LIFTING FAILED] " << r.lift_error << "\n";
        }
        else
        {
            if (r.lift_stats)
                r.lift_stats->print(f);
            else
                f << "[LIFTING OK] no lift stats available\n";
        }
    }

    if (r.raw_vs_native || r.raw_vs_native_dive)
    {
        std::ofstream f(out_dir / (prefix + ".stage1.report.txt"));
        if (r.raw_vs_native)
            r.raw_vs_native->print(f);
        if (r.raw_vs_native_dive)
        {
            f << "  [DEEP DIVE S1 1/1]\n";
            r.raw_vs_native_dive->print(f);
        }
    }

    if (r.opt_vs_raw || r.opt_vs_raw_dive)
    {
        std::ofstream f(out_dir / (prefix + ".stage2.report.txt"));
        if (!r.opt_transform_error.empty())
            f << "[STAGE 2 ERROR] " << r.opt_transform_error << "\n";
        if (r.opt_vs_raw)
            r.opt_vs_raw->print(f);
        if (r.opt_vs_raw_dive)
        {
            f << "  [DEEP DIVE S2 1/1]\n";
            r.opt_vs_raw_dive->print(f);
        }
    }
}

namespace {

double phase_coverage_pct(const VerificationPhaseResult &phase, size_t bbs_total)
{
    return phase.report ? coverage_pct(*phase.report, bbs_total) : 0.0;
}

size_t phase_failure_count(const VerificationPhaseResult &phase)
{
    return phase.report ? phase.report->total_failures() : 0;
}

double phase_total_ms(const VerificationPhaseResult &phase)
{
    if (!phase.report)
        return 0.0;
    auto [src_ms, tgt_ms] = pipeline_executor_ms(*phase.report);
    return src_ms + tgt_ms;
}

void write_phase_report_file(const fs::path &path,
                             std::string_view label,
                             const VerificationPhaseResult &phase)
{
    std::ofstream f(path);
    if (!f)
    {
        llvm::errs() << "  [WARN] cannot write phase report '" << path.string() << "'\n";
        return;
    }

    f << "[" << label << "] " << phase_status_name(phase.status) << "\n";
    if (!phase.skip_reason.empty())
        f << "[SKIP REASON] " << phase.skip_reason << "\n";
    if (!phase.error.empty())
        f << "[ERROR] " << phase.error << "\n";
    if (phase.report)
        phase.report->print(f);
    if (phase.deep_dive)
    {
        f << "  [DEEP DIVE 1/1]\n";
        phase.deep_dive->print(f);
    }
}

llvm::json::Object phase_json(const VerificationPhaseResult &phase, size_t bbs_total)
{
    llvm::json::Object obj;
    obj["status"] = phase_status_name(phase.status);
    obj["skip_reason"] = phase.skip_reason;
    obj["error"] = phase.error;
    obj["coverage_pct"] = phase_coverage_pct(phase, bbs_total);
    obj["failures"] = static_cast<int64_t>(phase_failure_count(phase));
    obj["test_ms"] = phase_total_ms(phase);
    return obj;
}

llvm::json::Object mutation_json(const MutationPhaseResult &mutation)
{
    llvm::json::Object obj;
    obj["status"] = mutation_phase_status_name(mutation.status);
    obj["skip_reason"] = mutation.skip_reason;
    obj["error"] = mutation.error;
    if (mutation.report)
    {
        llvm::json::Object rpt;
        rpt["total_enumerated"] = static_cast<int64_t>(mutation.report->total_enumerated);
        rpt["total_mutants"] = static_cast<int64_t>(mutation.report->total_mutants);
        rpt["budget"] = static_cast<int64_t>(mutation.report->budget_requested);
        rpt["killed"] = static_cast<int64_t>(mutation.report->killed);
        rpt["survived"] = static_cast<int64_t>(mutation.report->survived);
        rpt["equivalent"] = static_cast<int64_t>(mutation.report->equivalent);
        rpt["errors"] = static_cast<int64_t>(mutation.report->errors);
        rpt["mutation_score_pct"] = mutation.report->mutation_score() * 100.0;
        rpt["adjusted_score_pct"] = mutation.report->adjusted_score() * 100.0;
        rpt["lift_duration_ms"] = mutation.report->lift_duration_ms;
        rpt["campaign_duration_ms"] = mutation.report->campaign_duration_ms;
        obj["report"] = std::move(rpt);
    }
    return obj;
}

std::string phase_failure_summary(const std::vector<std::string> &labels)
{
    if (labels.empty())
        return "---";
    std::string joined;
    for (size_t i = 0; i < labels.size(); ++i)
    {
        if (i > 0)
            joined += "; ";
        joined += labels[i];
    }
    return joined;
}

} // namespace

void write_function_dot(const EvaluatedFunction &result,
                        const fs::path &out_dir,
                        const std::string &render_fmt)
{
    if (!result.record.cfg)
        return;

    lifted::visualization::CfgDotOptions cfg_opts;
    cfg_opts.graph_title = result.binary + "::" + result.func;
    std::string dot;

    if (result.record.raw_vs_native.report)
    {
        lifted::visualization::OverlayData od;
        od.block_hits = &result.record.raw_vs_native.report->src_block_hits;
        for (const auto &stg : result.record.raw_vs_native.report->stages)
        {
            if (!stg.divergences.empty())
            {
                od.divergence = &stg.divergences[0];
                break;
            }
        }
        lifted::visualization::OverlayOptions oo;
        oo.cfg_opts = cfg_opts;
        dot = lifted::visualization::overlay_to_dot(*result.record.cfg, od, oo);
    }
    else
    {
        dot = lifted::visualization::cfg_to_dot(*result.record.cfg, cfg_opts);
    }

    const fs::path dot_path = out_dir / (result.binary + "_" + result.func + ".dot");
    {
        std::error_code ec;
        llvm::raw_fd_ostream os(dot_path.string(), ec);
        if (ec)
        {
            llvm::errs() << "  [WARN] cannot write DOT '" << dot_path.string() << "': "
                         << ec.message() << "\n";
            return;
        }
        os << dot;
    }

    if (!render_fmt.empty())
    {
        fs::path rendered = fs::path(dot_path).replace_extension("." + render_fmt);
        std::string cmd = "dot -T" + render_fmt + " -o " + rendered.string() + " " + dot_path.string();
        if (std::system(cmd.c_str()) != 0)
            llvm::errs() << "  [WARN] graphviz render failed for " << dot_path.string() << "\n";
    }
}

void write_function_reports(const EvaluatedFunction &result,
                            const fs::path &out_dir)
{
    const std::string prefix = result.binary + "_" + result.func;

    {
        std::ofstream f(out_dir / (prefix + ".lift.report.txt"));
        if (!f)
        {
            llvm::errs() << "  [WARN] cannot write lift report for " << result.func << "\n";
            return;
        }
        if (result.record.lift_failed)
            f << "[LIFTING FAILED] " << result.record.lift_error << "\n";
        else if (result.record.lift_stats)
            result.record.lift_stats->print(f);
        else
            f << "[LIFTING OK] no lift stats available\n";
    }

    write_phase_report_file(out_dir / (prefix + ".raw_native.report.txt"),
                            "EG1 raw lifted IR vs native binary",
                            result.record.raw_vs_native);
    write_phase_report_file(out_dir / (prefix + ".o2_raw.report.txt"),
                            "EG2 raw lifted IR vs O2 IR",
                            result.record.opt_vs_raw);
    write_phase_report_file(out_dir / (prefix + ".o2_selftest.report.txt"),
                            "EG3 O2 self-test",
                            result.record.opt_selftest);

    std::ofstream f(out_dir / (prefix + ".mutation.report.txt"));
    if (!f)
    {
        llvm::errs() << "  [WARN] cannot write mutation report for " << result.func << "\n";
        return;
    }
    if (result.record.mutation.report)
    {
        result.record.mutation.report->print(f);
        return;
    }

    f << "=== MUTATION REPORT: " << result.func << " ===\n";
    f << "Binary: " << result.binary << "\n";
    f << "Status: " << mutation_phase_status_name(result.record.mutation.status) << "\n";
    if (!result.record.mutation.skip_reason.empty())
        f << "Skip reason: " << result.record.mutation.skip_reason << "\n";
    if (!result.record.mutation.error.empty())
        f << "Error: " << result.record.mutation.error << "\n";
    f << "EG1 status: " << phase_status_name(result.record.raw_vs_native.status) << "\n";
    f << "EG2 status: " << phase_status_name(result.record.opt_vs_raw.status) << "\n";
    f << "Self-test status: " << phase_status_name(result.record.opt_selftest.status) << "\n";
}

void write_campaign_artifacts(const std::string &campaign_label,
                              const std::vector<EvaluatedFunction> &results,
                              const fs::path &out_dir)
{
    std::ofstream report(out_dir / "report.txt");
    std::ofstream csv(out_dir / "summary.csv");
    std::ofstream json(out_dir / "summary.json");
    std::ofstream eg1_csv(out_dir / "eg1_summary.csv");
    std::ofstream eg2_csv(out_dir / "eg2_summary.csv");
    std::ofstream eg3_csv(out_dir / "eg3_summary.csv");
    std::ofstream eg1_json(out_dir / "eg1_summary.json");
    std::ofstream eg2_json(out_dir / "eg2_summary.json");
    std::ofstream eg3_json(out_dir / "eg3_summary.json");

    const std::string suite = results.empty() ? "" : results.front().suite;
    const std::string obfuscator = results.empty() ? "" : results.front().obfuscator;

    size_t attempted = results.size();
    size_t lift_succeeded = 0;
    size_t eg1_tested = 0;
    size_t eg1_pass = 0;
    size_t eg2_tested = 0;
    size_t eg2_pass = 0;
    size_t self_tested = 0;
    size_t self_pass = 0;
    size_t mutation_executed = 0;
    size_t mutation_skipped = 0;
    size_t mutation_errors = 0;
    size_t lift_failures = 0;
    size_t raw_gate_failures = 0;
    size_t o2_gate_failures = 0;
    size_t self_gate_failures = 0;
    double total_lift_ms = 0.0;
    double eg1_total_ms = 0.0;
    double eg2_total_ms = 0.0;
    double self_total_ms = 0.0;
    double eg1_cov_sum = 0.0;
    double eg2_cov_sum = 0.0;
    size_t eg1_cov_count = 0;
    size_t eg2_cov_count = 0;
    size_t total_enumerated = 0;
    size_t total_mutants = 0;
    size_t total_killed = 0;
    size_t total_survived = 0;
    size_t total_equivalent = 0;
    size_t total_errors = 0;

    std::vector<std::string> eg1_failures;
    std::vector<std::string> eg2_failures;
    std::vector<std::string> mutation_skip_labels;

    if (csv)
    {
        csv << "binary,func,obfuscator,bbs_total,"
               "lift_result,raw_native_result,raw_native_coverage_pct,raw_native_failures,"
               "o2_raw_result,o2_raw_coverage_pct,o2_raw_failures,"
               "o2_selftest_result,o2_selftest_coverage_pct,o2_selftest_failures,"
               "mutation_result,mutation_skip_reason,total_enumerated,total_mutants,budget,"
               "killed,survived,equivalent,errors,mutation_score_pct,adjusted_score_pct,"
               "lift_ms,eg1_test_ms,eg2_test_ms,o2_selftest_ms,mutation_ms\n";
    }

    llvm::json::Array function_rows;

    for (const auto &entry : results)
    {
        const auto &record = entry.record;
        const size_t bbs_total = record.bbs_total();
        const double eg1_cov = phase_coverage_pct(record.raw_vs_native, bbs_total);
        const double eg2_cov = phase_coverage_pct(record.opt_vs_raw, bbs_total);
        const double self_cov = phase_coverage_pct(record.opt_selftest, bbs_total);
        const size_t eg1_failures_count = phase_failure_count(record.raw_vs_native);
        const size_t eg2_failures_count = phase_failure_count(record.opt_vs_raw);
        const size_t self_failures_count = phase_failure_count(record.opt_selftest);
        const double eg1_ms = phase_total_ms(record.raw_vs_native);
        const double eg2_ms = phase_total_ms(record.opt_vs_raw);
        const double self_ms = phase_total_ms(record.opt_selftest);

        if (record.lift_failed)
            ++lift_failures;
        else
        {
            ++lift_succeeded;
            if (record.lift_stats)
                total_lift_ms += record.lift_stats->total_time_ms;
        }

        if (record.raw_vs_native.status != PhaseStatus::NOT_RUN &&
            record.raw_vs_native.status != PhaseStatus::SKIPPED)
            ++eg1_tested;
        if (record.raw_vs_native.status == PhaseStatus::PASS)
        {
            ++eg1_pass;
            eg1_cov_sum += eg1_cov;
            ++eg1_cov_count;
        }
        else if (record.raw_vs_native.status == PhaseStatus::FAIL ||
                 record.raw_vs_native.status == PhaseStatus::ERROR)
        {
            ++raw_gate_failures;
            eg1_failures.push_back(entry.binary + "::" + entry.func);
        }
        eg1_total_ms += eg1_ms;

        if (record.opt_vs_raw.status != PhaseStatus::NOT_RUN &&
            record.opt_vs_raw.status != PhaseStatus::SKIPPED)
            ++eg2_tested;
        if (record.opt_vs_raw.status == PhaseStatus::PASS)
        {
            ++eg2_pass;
            eg2_cov_sum += eg2_cov;
            ++eg2_cov_count;
        }
        else if (record.opt_vs_raw.status == PhaseStatus::FAIL ||
                 record.opt_vs_raw.status == PhaseStatus::ERROR)
        {
            ++o2_gate_failures;
            eg2_failures.push_back(entry.binary + "::" + entry.func);
        }
        eg2_total_ms += eg2_ms;

        if (record.opt_selftest.status != PhaseStatus::NOT_RUN &&
            record.opt_selftest.status != PhaseStatus::SKIPPED)
            ++self_tested;
        if (record.opt_selftest.status == PhaseStatus::PASS)
            ++self_pass;
        else if (record.opt_selftest.status == PhaseStatus::FAIL ||
                 record.opt_selftest.status == PhaseStatus::ERROR)
            ++self_gate_failures;
        self_total_ms += self_ms;

        if (record.mutation.status == MutationPhaseStatus::RUN && record.mutation.report)
        {
            ++mutation_executed;
            total_enumerated += record.mutation.report->total_enumerated;
            total_mutants += record.mutation.report->total_mutants;
            total_killed += record.mutation.report->killed;
            total_survived += record.mutation.report->survived;
            total_equivalent += record.mutation.report->equivalent;
            total_errors += record.mutation.report->errors;
        }
        else if (record.mutation.status == MutationPhaseStatus::ERROR)
        {
            ++mutation_errors;
            mutation_skip_labels.push_back(entry.binary + "::" + entry.func);
        }
        else if (record.mutation.status == MutationPhaseStatus::SKIPPED)
        {
            ++mutation_skipped;
            mutation_skip_labels.push_back(entry.binary + "::" + entry.func + " [" + record.mutation.skip_reason + "]");
        }

        if (csv)
        {
            csv << entry.binary << "," << entry.func << "," << entry.obfuscator << ","
                << bbs_total << ","
                << (record.lift_failed ? "FAIL" : "PASS") << ","
                << phase_status_name(record.raw_vs_native.status) << "," << fmt_dbl(eg1_cov, 2) << "," << eg1_failures_count << ","
                << phase_status_name(record.opt_vs_raw.status) << "," << fmt_dbl(eg2_cov, 2) << "," << eg2_failures_count << ","
                << phase_status_name(record.opt_selftest.status) << "," << fmt_dbl(self_cov, 2) << "," << self_failures_count << ","
                << mutation_phase_status_name(record.mutation.status) << "," << record.mutation.skip_reason << ","
                << (record.mutation.report ? record.mutation.report->total_enumerated : 0) << ","
                << (record.mutation.report ? record.mutation.report->total_mutants : 0) << ","
                << (record.mutation.report ? record.mutation.report->budget_requested : 0) << ","
                << (record.mutation.report ? record.mutation.report->killed : 0) << ","
                << (record.mutation.report ? record.mutation.report->survived : 0) << ","
                << (record.mutation.report ? record.mutation.report->equivalent : 0) << ","
                << (record.mutation.report ? record.mutation.report->errors : 0) << ","
                << fmt_dbl(record.mutation.report ? record.mutation.report->mutation_score() * 100.0 : 0.0, 2) << ","
                << fmt_dbl(record.mutation.report ? record.mutation.report->adjusted_score() * 100.0 : 0.0, 2) << ","
                << fmt_dbl(record.lift_stats ? record.lift_stats->total_time_ms : 0.0, 2) << ","
                << fmt_dbl(eg1_ms, 2) << "," << fmt_dbl(eg2_ms, 2) << "," << fmt_dbl(self_ms, 2) << ","
                << fmt_dbl(record.mutation.report ? record.mutation.report->campaign_duration_ms : 0.0, 2) << "\n";
        }

        llvm::json::Object obj;
        obj["suite"] = entry.suite;
        obj["binary"] = entry.binary;
        obj["func"] = entry.func;
        obj["obfuscator"] = entry.obfuscator;
        obj["bbs_total"] = static_cast<int64_t>(bbs_total);
        obj["lift_result"] = record.lift_failed ? "FAIL" : "PASS";
        obj["lift_error"] = record.lift_error;
        obj["lift_ms"] = record.lift_stats ? record.lift_stats->total_time_ms : 0.0;
        obj["raw_native"] = phase_json(record.raw_vs_native, bbs_total);
        obj["o2_raw"] = phase_json(record.opt_vs_raw, bbs_total);
        obj["o2_selftest"] = phase_json(record.opt_selftest, bbs_total);
        obj["mutation"] = mutation_json(record.mutation);
        function_rows.push_back(std::move(obj));
    }

    if (json)
    {
        std::string json_buffer;
        llvm::raw_string_ostream raw(json_buffer);
        llvm::json::OStream os(raw, 2);
        os.object([&] {
            os.attribute("campaign", campaign_label);
            os.attribute("suite", suite);
            os.attribute("obfuscator", obfuscator);
            os.attributeArray("functions", [&] {
                for (auto &row : function_rows)
                    os.value(row);
            });
        });
        raw.flush();
        json << json_buffer << "\n";
    }

    const double eg1_pass_pct = eg1_tested ? 100.0 * static_cast<double>(eg1_pass) / static_cast<double>(eg1_tested) : 0.0;
    const double eg2_pass_pct = eg2_tested ? 100.0 * static_cast<double>(eg2_pass) / static_cast<double>(eg2_tested) : 0.0;
    const double eg1_cov_avg = eg1_cov_count ? eg1_cov_sum / static_cast<double>(eg1_cov_count) : 0.0;
    const double eg2_cov_avg = eg2_cov_count ? eg2_cov_sum / static_cast<double>(eg2_cov_count) : 0.0;
    const double avg_lift_s = lift_succeeded ? (total_lift_ms / static_cast<double>(lift_succeeded)) / 1000.0 : 0.0;
    const double avg_eg1_s = eg1_tested ? (eg1_total_ms / static_cast<double>(eg1_tested)) / 1000.0 : 0.0;
    const double avg_eg2_s = eg2_tested ? (eg2_total_ms / static_cast<double>(eg2_tested)) / 1000.0 : 0.0;
    const double overall_mutation_score = total_mutants ? 100.0 * static_cast<double>(total_killed) / static_cast<double>(total_mutants) : 0.0;
    const double adjusted_mutation_score = (total_mutants > total_equivalent)
        ? 100.0 * static_cast<double>(total_killed) / static_cast<double>(total_mutants - total_equivalent)
        : 0.0;

    if (report)
    {
        report << "=== EVALUATION REPORT: " << campaign_label << " ===\n\n";
        report << "--- Campaign Metadata ---\n";
        report << "Suite: " << suite << "\n";
        report << "Obfuscator: " << obfuscator << "\n";
        report << "Functions attempted: " << attempted << "\n\n";

        report << "--- Phase Eligibility ---\n";
        report << "Lift succeeded: " << lift_succeeded << "\n";
        report << "EG1 pass: " << eg1_pass << "/" << eg1_tested << "\n";
        report << "EG2 pass: " << eg2_pass << "/" << eg2_tested << "\n";
        report << "O2 self-test pass: " << self_pass << "/" << self_tested << "\n";
        report << "Mutation executed: " << mutation_executed << "\n\n";

        report << "--- Failure Buckets ---\n";
        report << "Lift failures: " << lift_failures << "\n";
        report << "Raw/native failures: " << raw_gate_failures << "\n";
        report << "O2/raw failures: " << o2_gate_failures << "\n";
        report << "O2 self-test failures: " << self_gate_failures << "\n";
        report << "Mutation skipped: " << mutation_skipped << "\n";
        report << "Mutation errors: " << mutation_errors << "\n\n";

        report << "--- EG1: Raw lifted IR vs native binary ---\n";
        report << "Pass %: " << fmt_dbl(eg1_pass_pct, 1) << "\n";
        report << "Avg coverage % (PASS only): " << fmt_dbl(eg1_cov_avg, 1) << "\n";
        report << "Avg lift (s): " << fmt_dbl(avg_lift_s, 3) << "\n";
        report << "Avg test (s): " << fmt_dbl(avg_eg1_s, 3) << "\n";
        report << "Failures: " << phase_failure_summary(eg1_failures) << "\n\n";

        report << "--- EG2: Raw lifted IR vs O2 IR ---\n";
        report << "Pass %: " << fmt_dbl(eg2_pass_pct, 1) << "\n";
        report << "Avg coverage % (PASS only): " << fmt_dbl(eg2_cov_avg, 1) << "\n";
        report << "Avg lift (s): " << fmt_dbl(avg_lift_s, 3) << "\n";
        report << "Avg test (s): " << fmt_dbl(avg_eg2_s, 3) << "\n";
        report << "Failures: " << phase_failure_summary(eg2_failures) << "\n\n";

        report << "--- EG3: O2 self-test + mutation campaign ---\n";
        report << "Self-test pass: " << self_pass << "/" << self_tested << "\n";
        report << "Mutants enumerated: " << total_enumerated << "\n";
        report << "Mutants tested: " << total_mutants << "\n";
        report << "Killed: " << total_killed << "\n";
        report << "Survived: " << total_survived << "\n";
        report << "Equivalent: " << total_equivalent << "\n";
        report << "Errors: " << total_errors << "\n";
        report << "Mutation score %: " << fmt_dbl(overall_mutation_score, 1) << "\n";
        report << "Adjusted score %: " << fmt_dbl(adjusted_mutation_score, 1) << "\n";
        report << "Skipped/blocked: " << phase_failure_summary(mutation_skip_labels) << "\n";
    }

    auto write_table_row = [&](std::ofstream &out,
                               const std::string &failure_summary,
                               size_t functions_tested,
                               double pass_pct,
                               double cov_pct,
                               double avg_test_s)
    {
        if (!out)
            return;
        out << "suite,obfuscator,functions_total,functions_tested,pass_pct,avg_coverage_pct,avg_lift_s,avg_test_s,failure_summary\n";
        out << suite << "," << obfuscator << "," << attempted << "," << functions_tested << ","
            << fmt_dbl(pass_pct, 1) << "," << fmt_dbl(cov_pct, 1) << ","
            << fmt_dbl(avg_lift_s, 3) << "," << fmt_dbl(avg_test_s, 3) << ","
            << failure_summary << "\n";
    };

    write_table_row(eg1_csv, phase_failure_summary(eg1_failures), eg1_tested, eg1_pass_pct, eg1_cov_avg, avg_eg1_s);
    write_table_row(eg2_csv, phase_failure_summary(eg2_failures), eg2_tested, eg2_pass_pct, eg2_cov_avg, avg_eg2_s);

    if (eg3_csv)
    {
        eg3_csv << "suite,obfuscator,functions_total,lift_failures,raw_gate_failures,o2_gate_failures,o2_selftest_failures,mutation_executed,mutation_skipped,mutation_errors,total_enumerated,total_mutants,killed,survived,equivalent,errors,mutation_score_pct,adjusted_score_pct\n";
        eg3_csv << suite << "," << obfuscator << "," << attempted << ","
                << lift_failures << "," << raw_gate_failures << "," << o2_gate_failures << ","
                << self_gate_failures << "," << mutation_executed << "," << mutation_skipped << "," << mutation_errors << ","
                << total_enumerated << "," << total_mutants << "," << total_killed << "," << total_survived << ","
                << total_equivalent << "," << total_errors << ","
                << fmt_dbl(overall_mutation_score, 1) << "," << fmt_dbl(adjusted_mutation_score, 1) << "\n";
    }

    auto write_json_summary = [&](std::ofstream &out,
                                  size_t functions_tested,
                                  double pass_pct,
                                  double cov_pct,
                                  double avg_test_s,
                                  const std::vector<std::string> &failure_labels)
    {
        if (!out)
            return;
        std::string json_buffer;
        llvm::raw_string_ostream raw(json_buffer);
        llvm::json::OStream os(raw, 2);
        os.object([&] {
            os.attribute("suite", suite);
            os.attribute("obfuscator", obfuscator);
            os.attribute("functions_total", static_cast<int64_t>(attempted));
            os.attribute("functions_tested", static_cast<int64_t>(functions_tested));
            os.attribute("pass_pct", pass_pct);
            os.attribute("avg_coverage_pct", cov_pct);
            os.attribute("avg_lift_s", avg_lift_s);
            os.attribute("avg_test_s", avg_test_s);
            os.attributeArray("failure_summary", [&] {
                for (const auto &label : failure_labels)
                    os.value(label);
            });
        });
        raw.flush();
        out << json_buffer << "\n";
    };

    write_json_summary(eg1_json, eg1_tested, eg1_pass_pct, eg1_cov_avg, avg_eg1_s, eg1_failures);
    write_json_summary(eg2_json, eg2_tested, eg2_pass_pct, eg2_cov_avg, avg_eg2_s, eg2_failures);

    if (eg3_json)
    {
        std::string json_buffer;
        llvm::raw_string_ostream raw(json_buffer);
        llvm::json::OStream os(raw, 2);
        os.object([&] {
            os.attribute("suite", suite);
            os.attribute("obfuscator", obfuscator);
            os.attribute("functions_total", static_cast<int64_t>(attempted));
            os.attribute("lift_failures", static_cast<int64_t>(lift_failures));
            os.attribute("raw_gate_failures", static_cast<int64_t>(raw_gate_failures));
            os.attribute("o2_gate_failures", static_cast<int64_t>(o2_gate_failures));
            os.attribute("o2_selftest_failures", static_cast<int64_t>(self_gate_failures));
            os.attribute("mutation_executed", static_cast<int64_t>(mutation_executed));
            os.attribute("mutation_skipped", static_cast<int64_t>(mutation_skipped));
            os.attribute("mutation_errors", static_cast<int64_t>(mutation_errors));
            os.attribute("total_enumerated", static_cast<int64_t>(total_enumerated));
            os.attribute("total_mutants", static_cast<int64_t>(total_mutants));
            os.attribute("killed", static_cast<int64_t>(total_killed));
            os.attribute("survived", static_cast<int64_t>(total_survived));
            os.attribute("equivalent", static_cast<int64_t>(total_equivalent));
            os.attribute("errors", static_cast<int64_t>(total_errors));
            os.attribute("mutation_score_pct", overall_mutation_score);
            os.attribute("adjusted_score_pct", adjusted_mutation_score);
        });
        raw.flush();
        eg3_json << json_buffer << "\n";
    }
}


} // namespace lifted::eval
