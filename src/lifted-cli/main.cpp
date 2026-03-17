// lifted-cli — interactive and agent-driven lifting & verification tool.
//
// Subcommands:
//   list    List all known suites, targets, and functions.
//   suite   Run all targets in a named suite (or CSV file).
//   target  Run all functions in one suite target.
//   fn      Run a single function (three input modes).
//
// Exit codes:
//   0  All tested functions PASS.
//   1  At least one divergence (FAIL_DIVERGED).
//   2  Fatal error (parse/lift/pipeline failure, or invalid arguments).
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/raw_ostream.h>

#include "abi/all_registers_cc.hpp"
#include "abi/systemv_x64.hpp"
#include "eval_pipeline.hpp"
#include "mutation_campaign.hpp"
#include "suite.hpp"
#include "utils.hpp"

#include "compat/lief_compat.hpp"

#include "visualization/cfg_dot.hpp"
#include "visualization/pipeline_overlay.hpp"
#include <algorithm>
#include <iomanip>

#include <cstdio> // snprintf
#include <filesystem>
#include <fstream> // std::ofstream
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "lifter/lifter.hpp"
#include "lifter/polaris_lifter_callbacks.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <glog/logging.h>

namespace fs = std::filesystem;
using namespace llvm;
using namespace lifted::eval;
using namespace lifted::fault_injection;

// ── Subcommands ────────────────────────────────────────────────────────────────

// Hide LLVM's internal options (debug, stats, etc.) from --help output.
// Subcommand descriptions are not options and survive this filter.
static cl::OptionCategory LiftedCLICategory("lifted-cli options");
static cl::SubCommand ListCmd("list", "List suites, targets and functions");
static cl::SubCommand SuiteCmd("suite", "Run all targets in a named suite");
static cl::SubCommand TargetCmd("target", "Run all functions in one suite target");
static cl::SubCommand FnCmd("fn", "Run a single function");
static cl::SubCommand GraphCmd("graph", "Generate CFG DOT output for a single function");
static cl::SubCommand MutateCmd("mutate", "Run fault-injection mutation campaign on a single function");
// ── list options ───────────────────────────────────────────────────────────────

static cl::opt<std::string> ListSuite(
    "suite",
    cl::desc("Suite to inspect (default: all known suites)"),
    cl::sub(ListCmd),
    cl::Optional);
// ── suite options ──────────────────────────────────────────────────────────────

static cl::opt<std::string> SuiteName(
    "suite",
    cl::desc("Named suite (synthetic, tum-basic-algorithms, etc.) or path to suite CSV"),
    cl::sub(SuiteCmd),
    cl::Required);
static cl::list<std::string> SuiteIgnore(
    "ignore",
    cl::desc("Target stems to skip (comma-separated, e.g. arithmetic,branch)"),
    cl::sub(SuiteCmd),
    cl::CommaSeparated);
static cl::opt<int> SuiteMaxDeepDives(
    "max-deep-dives",
    cl::desc("Deep-dive divergences per function: 0=skip, 1=first (default)"),
    cl::sub(SuiteCmd),
    cl::init(1));
static cl::opt<std::string> SuiteObfuscator(
    "obfuscator",
    cl::desc("Filter entries by obfuscator: none, polaris, or all (default: all)"),
    cl::sub(SuiteCmd),
    cl::init("all"));
static cl::opt<std::string> SuiteOutputDir(
    "output-dir",
    cl::desc("Directory for reports, CSV, and DOT output"),
    cl::sub(SuiteCmd));
static cl::opt<std::string> SuiteRenderCfg(
    "render-cfg",
    cl::desc("Render CFGs via graphviz (svg|png|pdf); requires --output-dir"),
    cl::sub(SuiteCmd));
static cl::opt<bool> SuiteNoFullPipeline(
    "no-full-pipeline",
    cl::desc("Run only Stage 1 (raw vs Unicorn), skip O2 verification"),
    cl::sub(SuiteCmd),
    cl::init(false));

// ── target options ─────────────────────────────────────────────────────────────

static cl::opt<std::string> TargetSuite(
    "suite",
    cl::desc("Suite name or CSV path to search"),
    cl::sub(TargetCmd),
    cl::Required);
static cl::opt<std::string> TargetName(
    "target",
    cl::desc("Target stem to run (e.g. arithmetic)"),
    cl::sub(TargetCmd),
    cl::Required);
static cl::list<std::string> TargetIgnore(
    "ignore",
    cl::desc("Function names to skip (comma-separated)"),
    cl::sub(TargetCmd),
    cl::CommaSeparated);
static cl::opt<int> TargetMaxDeepDives(
    "max-deep-dives",
    cl::desc("Deep-dive divergences per function: 0=skip, 1=first (default)"),
    cl::sub(TargetCmd),
    cl::init(1));
static cl::opt<std::string> TargetObfuscator(
    "obfuscator",
    cl::desc("Filter entries by obfuscator: none, polaris, or all (default: all)"),
    cl::sub(TargetCmd),
    cl::init("all"));
static cl::opt<std::string> TargetOutputDir(
    "output-dir",
    cl::desc("Directory for reports, CSV, and DOT output"),
    cl::sub(TargetCmd));
static cl::opt<std::string> TargetRenderCfg(
    "render-cfg",
    cl::desc("Render CFGs via graphviz (svg|png|pdf); requires --output-dir"),
    cl::sub(TargetCmd));
static cl::opt<bool> TargetNoFullPipeline(
    "no-full-pipeline",
    cl::desc("Run only Stage 1 (raw vs Unicorn), skip O2 verification"),
    cl::sub(TargetCmd),
    cl::init(false));

// ── fn options ─────────────────────────────────────────────────────────────────
//
// Three mutually exclusive input modes (validated at runtime):
//   Mode A: --binary + --rva
//   Mode B: --binary + --export
//   Mode C: --suite  + --target + --func

static cl::opt<std::string> FnBinary(
    "binary",
    cl::desc("Path to ELF/PE/MachO binary"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnRva(
    "rva",
    cl::desc("Entry RVA in hex (e.g. 0x1234) — Mode A"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnExport(
    "export",
    cl::desc("Export symbol name; RVA resolved at runtime — Mode B"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnSuite(
    "suite",
    cl::desc("Suite name or CSV path — Mode C"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnTarget(
    "target",
    cl::desc("Target stem to locate in suite — Mode C"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnFunc(
    "func",
    cl::desc("Function name to locate in target CSV — Mode C"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnDisplayName(
    "name",
    cl::desc("Display name for output (default: export name, func name, or sub_<rva>)"),
    cl::sub(FnCmd));
static cl::opt<int> FnMaxDeepDives(
    "max-deep-dives",
    cl::desc("Deep-dive divergences: 0=skip, 1=first (default)"),
    cl::sub(FnCmd),
    cl::init(1));
static cl::opt<std::string> FnOutputDir(
    "output-dir",
    cl::desc("Directory for DOT output"),
    cl::sub(FnCmd));
static cl::opt<std::string> FnRenderCfg(
    "render-cfg",
    cl::desc("Render CFGs via graphviz (svg|png|pdf); requires --output-dir"),
    cl::sub(FnCmd));
static cl::opt<bool> FnNoFullPipeline(
    "no-full-pipeline",
    cl::desc("Run only Stage 1 (raw vs Unicorn), skip O2 verification"),
    cl::sub(FnCmd),
    cl::init(false));

// ── graph options ──────────────────────────────────────────────────────────────

static cl::opt<std::string> GraphBinary(
    "binary",
    cl::desc("Path to ELF/PE/MachO binary"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphRva(
    "rva",
    cl::desc("Entry RVA in hex (e.g. 0x1234) -- Mode A"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphExport(
    "export",
    cl::desc("Export symbol name; RVA resolved at runtime -- Mode B"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphSuite(
    "suite",
    cl::desc("Suite name or CSV path -- Mode C"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphTarget(
    "target",
    cl::desc("Target stem to locate in suite -- Mode C"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphFunc(
    "func",
    cl::desc("Function name to locate in target CSV -- Mode C"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphDisplayName(
    "name",
    cl::desc("Display name for output (default: derived from export/func/rva)"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphOutput(
    "output",
    cl::desc("Write DOT to file (default: stdout)"),
    cl::sub(GraphCmd));
static cl::opt<std::string> GraphRender(
    "render",
    cl::desc("Render DOT to image via graphviz dot (svg, png, pdf); implies --output"),
    cl::sub(GraphCmd));
static cl::opt<bool> GraphOverlay(
    "overlay",
    cl::desc("Run pipeline and overlay results on CFG"),
    cl::sub(GraphCmd),
    cl::init(false));
static cl::opt<bool> GraphMergeSynthetic(
    "merge-synthetic",
    cl::desc("Merge synthetic blocks into callers (IDA-style)"),
    cl::sub(GraphCmd),
    cl::init(false));
static cl::opt<int> GraphMaxDeepDives(
    "max-deep-dives",
    cl::desc("Deep-dive divergences for overlay mode: 0=skip, 1=first (default)"),
    cl::sub(GraphCmd),
    cl::init(1));
static cl::opt<int> GraphDivergenceIdx(
    "divergence-idx",
    cl::desc("Which divergence to highlight in overlay (0 = first, default)"),
    cl::sub(GraphCmd),
    cl::init(0));

// ── mutate options ────────────────────────────────────────────────────────────
//
// Three mutually exclusive input modes (same as fn subcommand):
//   Mode A: --binary + --rva
//   Mode B: --binary + --export
//   Mode C: --suite  + --target + --func

static cl::opt<std::string> MutateBinary(
    "binary",
    cl::desc("Path to ELF/PE/MachO binary"),
    cl::sub(MutateCmd));
static cl::opt<std::string> MutateRva(
    "rva",
    cl::desc("Entry RVA in hex (e.g. 0x1234) — Mode A"),
    cl::sub(MutateCmd));
static cl::opt<std::string> MutateExport(
    "export",
    cl::desc("Export symbol name; RVA resolved at runtime — Mode B"),
    cl::sub(MutateCmd));
static cl::opt<std::string> MutateSuite(
    "suite",
    cl::desc("Suite name or CSV path — Mode C"),
    cl::sub(MutateCmd));
static cl::opt<std::string> MutateTarget(
    "target",
    cl::desc("Target stem to locate in suite — Mode C"),
    cl::sub(MutateCmd));
static cl::opt<std::string> MutateFunc(
    "func",
    cl::desc("Function name to locate in target CSV — Mode C"),
    cl::sub(MutateCmd));
static cl::opt<int> MutateBudget(
    "budget",
    cl::desc("Max mutation points to test (default: 200)"),
    cl::sub(MutateCmd),
    cl::init(200));
static cl::opt<std::string> MutateSeed(
    "seed",
    cl::desc("RNG seed in hex (default: 0x1337)"),
    cl::sub(MutateCmd),
    cl::init("0x1337"));
static cl::list<std::string> MutateCategories(
    "categories",
    cl::desc("Comma-separated category filter (e.g. arithmetic,comparison_bdry); default: all"),
    cl::sub(MutateCmd),
    cl::CommaSeparated);
static cl::opt<std::string> MutateOutputDir(
    "output-dir",
    cl::desc("Directory for per-function mutation reports, summary.csv, and report.txt"),
    cl::sub(MutateCmd));
static cl::opt<std::string> MutateObfuscator(
    "obfuscator",
    cl::desc("Filter suite entries by obfuscator: none, polaris, or all (default: all) -- Mode D only"),
    cl::sub(MutateCmd),
    cl::init("all"));
static cl::list<std::string> MutateIgnore(
    "ignore",
    cl::desc("Target stems to skip in suite mode (comma-separated) -- Mode D only"),
    cl::sub(MutateCmd),
    cl::CommaSeparated);
// ── Helpers ────────────────────────────────────────────────────────────────────

// Derive a short identifying stem from a .so path.
// "/build/.../libeval-arithmetic.so" -> "arithmetic"
static std::string target_stem(const fs::path &so_path)
{
    std::string stem = so_path.stem().string();
    if (stem.starts_with("libeval-"))
        return stem.substr(8);
    if (stem.starts_with("lib"))
        return stem.substr(3);
    return stem;
}

// Resolve a --suite argument: try named lookup first, then filesystem path.
static Expected<fs::path> resolve_suite_arg(const std::string &arg)
{
    if (auto p = resolve_suite_name(arg))
        return *p;

    fs::path p(arg);
    if (fs::exists(p))
        return p;

    auto known = known_suite_names();
    std::string known_list;
    for (size_t i = 0; i < known.size(); ++i)
    {
        if (i > 0)
            known_list += ", ";
        known_list += known[i];
    }
    return createStringError(inconvertibleErrorCode(),
                             "Unknown suite '" + arg + "'. Known names: [" + known_list + "]. "
                                                                                          "Pass a path to a suite CSV or use a known name.");
}

// ── Coverage helper ────────────────────────────────────────────────────────────

static double coverage_pct(const lifted::pipeline::PipelineReport &report, size_t bbs_total)
{
    if (bbs_total == 0 || report.stages.empty())
        return 0.0;
    return 100.0 * static_cast<double>(report.stages.back().cumulative_unique_blocks) /
           static_cast<double>(bbs_total);
}

// Sum executor wall-clock time across all stages of a pipeline report.
// Returns {src_ms, tgt_ms}.
static std::pair<double, double> pipeline_executor_ms(const lifted::pipeline::PipelineReport &r)
{
    double src = 0.0, tgt = 0.0;
    for (const auto &stg : r.stages)
    {
        src += static_cast<double>(stg.src_wall_ns.count()) * 1e-6;
        tgt += static_cast<double>(stg.tgt_wall_ns.count()) * 1e-6;
    }
    return {src, tgt};
}

static std::string fmt_dbl(double v, int precision = 1)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%.*f", precision, v);
    return buf;
}

// ── CSV row ───────────────────────────────────────────────────────────────────

struct CsvRow
{
    std::string binary;
    std::string func;
    std::string obfuscator;
    size_t bbs_total = 0;
    std::string stage1_result; // PASS, FAIL, ERROR, LIFT_FAIL
    double stage1_coverage_pct = 0.0;
    std::string stage2_result; // PASS, FAIL, ERROR, N/A
    double stage2_coverage_pct = 0.0;
};

// ── Mutation CSV row ─────────────────────────────────────────────────────────

struct MutateRow
{
    std::string binary;
    std::string func;
    std::string obfuscator;
    bool   lift_failed       = false;
    size_t total_enumerated  = 0;
    size_t total_mutants     = 0;
    size_t budget            = 0;
    size_t killed            = 0;
    size_t survived          = 0;
    size_t equivalent        = 0;
    size_t errors            = 0;
    double mutation_score_pct  = 0.0;
    double adjusted_score_pct  = 0.0;
    double lift_duration_ms    = 0.0;
    double campaign_duration_ms = 0.0;
};

// ── Per-stage statistics ───────────────────────────────────────────────────────

struct StageStats
{
    size_t tested = 0;
    size_t pass = 0;
    size_t fail = 0;
    size_t errors = 0;
    // Coverage is accumulated only for PASS functions; divide by pass_cov_count for the mean.
    double total_coverage_pct = 0.0;
    size_t pass_cov_count = 0;
    // Executor wall-clock time summed across all tested functions (nanoseconds -> ms conversion
    // happens at accumulation; src = JIT side, tgt = Unicorn/comparison side).
    double total_src_wall_ms = 0.0;
    double total_tgt_wall_ms = 0.0;
    std::vector<std::string> failing;
};

// ── Run summary ────────────────────────────────────────────────────────────────

struct RunSummary
{
    StageStats stage1;
    StageStats stage2;
    std::vector<std::string> lift_errors;
    std::vector<CsvRow> csv_rows;
    // Lift wall-clock time summed across all successfully-lifted functions.
    double total_lift_ms = 0.0;
    size_t lift_count = 0;

    void record(const std::string &label,
                const FullPipelineResult &r,
                std::string_view binary = "",
                std::string_view func = "",
                std::string_view obfusc = "");

    void record_fatal(const std::string &label,
                      std::string_view binary = "",
                      std::string_view func = "",
                      std::string_view obfusc = "");

    int exit_code() const;
    void print_summary(const std::string &suite_label, std::ostream &os) const;
    void write_csv(const fs::path &path) const;
};

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

    // Stage 1
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

    // Stage 2
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
        // Stage 1 failed or --no-full-pipeline: N/A is not a failure.
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

    // Combined
    size_t full_pass = 0;
    size_t s1_no_s2 = 0;   // Stage 1 PASS but Stage 2 N/A (--no-full-pipeline)
    size_t s2_na_fail = 0; // Stage 2 N/A because Stage 1 failed
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
        errs() << "warning: cannot write CSV to '" << path.string() << "'\n";
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

// ── Mutation summary ──────────────────────────────────────────────────────────

struct MutateSummary
{
    size_t total_functions = 0;
    size_t lift_failures   = 0;
    size_t tested          = 0;

    size_t total_enumerated = 0;
    size_t total_mutants    = 0;
    size_t total_budget     = 0;
    size_t total_killed     = 0;
    size_t total_survived   = 0;
    size_t total_equivalent = 0;
    size_t total_errors     = 0;
    double sum_adjusted_score = 0.0;

    std::map<MutationCategory, std::pair<size_t, size_t>> agg_by_category;
    std::map<difficulty_t,     std::pair<size_t, size_t>> agg_by_difficulty;
    std::map<unsigned,         std::pair<size_t, size_t>> agg_by_width_bits;

    double total_lift_ms     = 0.0;
    double total_campaign_ms = 0.0;

    std::vector<std::string> perfect_kills;     // labels with 100% kill score
    std::vector<std::string> zero_kills;        // labels with 0% score and >= 5 mutants
    std::vector<std::string> lift_error_labels; // labels with lift/baseline failure
    std::vector<MutateRow>   csv_rows;

    void record(const std::string &label,
                const LiftAndMutateResult &r,
                std::string_view binary,
                std::string_view func,
                std::string_view obfusc);

    int  exit_code() const;
    void print_summary(const std::string &suite_label, std::ostream &os) const;
    void write_csv(const fs::path &path) const;
};

void MutateSummary::record(const std::string &label,
                           const LiftAndMutateResult &r,
                           std::string_view binary,
                           std::string_view func,
                           std::string_view obfusc)
{
    ++total_functions;

    MutateRow row;
    row.binary     = std::string(binary);
    row.func       = std::string(func);
    row.obfuscator = std::string(obfusc);

    // Treat lift_failed==true OR missing report (baseline failure) as a lift failure.
    if (r.lift_failed || !r.report)
    {
        ++lift_failures;
        row.lift_failed = true;
        lift_error_labels.push_back(label + ": " + r.lift_error);
        csv_rows.push_back(std::move(row));
        return;
    }

    ++tested;
    const auto &rpt = *r.report;

    row.total_enumerated     = rpt.total_enumerated;
    row.total_mutants        = rpt.total_mutants;
    row.budget               = rpt.budget_requested;
    row.killed               = rpt.killed;
    row.survived             = rpt.survived;
    row.equivalent           = rpt.equivalent;
    row.errors               = rpt.errors;
    row.mutation_score_pct   = rpt.mutation_score() * 100.0;
    row.adjusted_score_pct   = rpt.adjusted_score() * 100.0;
    row.lift_duration_ms     = rpt.lift_duration_ms;
    row.campaign_duration_ms = rpt.campaign_duration_ms;

    total_enumerated  += rpt.total_enumerated;
    total_mutants     += rpt.total_mutants;
    total_budget      += rpt.budget_requested;
    total_killed      += rpt.killed;
    total_survived    += rpt.survived;
    total_equivalent  += rpt.equivalent;
    total_errors      += rpt.errors;
    sum_adjusted_score += rpt.adjusted_score();
    total_lift_ms     += rpt.lift_duration_ms;
    total_campaign_ms += rpt.campaign_duration_ms;

    for (const auto &[cat, kt] : rpt.by_category)
    {
        auto &ag  = agg_by_category[cat];
        ag.first  += kt.first;
        ag.second += kt.second;
    }
    for (const auto &[diff, kt] : rpt.by_difficulty)
    {
        auto &ag  = agg_by_difficulty[diff];
        ag.first  += kt.first;
        ag.second += kt.second;
    }
    for (const auto &[w, kt] : rpt.by_width_bits)
    {
        auto &ag  = agg_by_width_bits[w];
        ag.first  += kt.first;
        ag.second += kt.second;
    }

    // Perfect kill: every mutant killed.
    if (rpt.total_mutants > 0 && rpt.killed == rpt.total_mutants)
        perfect_kills.push_back(label);
    // Zero kill: nothing killed despite enough mutants (and not all errors).
    if (rpt.total_mutants >= 5 && rpt.killed == 0 &&
        rpt.errors < rpt.total_mutants)
        zero_kills.push_back(label);

    csv_rows.push_back(std::move(row));
}

int MutateSummary::exit_code() const
{
    if (tested == 0 && total_functions > 0)
        return 2; // all functions failed to lift/run
    if (lift_failures > 0)
        return 1; // some lift failures but at least one succeeded
    return 0;
}

void MutateSummary::print_summary(const std::string &suite_label, std::ostream &os) const
{
    auto pct = [](size_t n, size_t d) -> double {
        return d > 0 ? 100.0 * static_cast<double>(n) / static_cast<double>(d) : 0.0;
    };

    os << "\n=== MUTATION CAMPAIGN REPORT: " << suite_label << " ===\n";

    os << "\n--- Functions ---\n";
    os << "  Attempted:           " << total_functions << "\n";
    os << "  Lift failures:       " << lift_failures   << "\n";
    os << "  Successfully tested: " << tested          << "\n";

    if (tested == 0)
    {
        os << "\n  No functions successfully tested.\n";
        if (!lift_error_labels.empty())
        {
            os << "\nLift failures:\n";
            for (const auto &e : lift_error_labels)
                os << "  " << e << "\n";
        }
        return;
    }

    os << "\n--- Mutation Statistics ---\n";
    os << "  Total enumerated:        " << total_enumerated << "\n";
    os << "  Total mutants tested:    " << total_mutants
       << "  (budget sum: " << total_budget << ")\n";
    os << "  Killed:     " << total_killed
       << "  (" << fmt_dbl(pct(total_killed, total_mutants)) << "%)\n";
    os << "  Survived:   " << total_survived
       << "  (" << fmt_dbl(pct(total_survived, total_mutants)) << "%)\n";
    os << "  Equivalent: " << total_equivalent
       << "  (" << fmt_dbl(pct(total_equivalent, total_mutants)) << "%)\n";
    os << "  Errors:     " << total_errors << "\n";

    os << "  Overall mutation score:          "
       << fmt_dbl(pct(total_killed, total_mutants)) << "%\n";

    double avg_adj = tested > 0
        ? sum_adjusted_score / static_cast<double>(tested) : 0.0;
    os << "  Avg adjusted score (per fn):     "
       << fmt_dbl(avg_adj * 100.0) << "%\n";

    // Median mutation score across tested functions.
    {
        std::vector<double> scores;
        scores.reserve(csv_rows.size());
        for (const auto &row : csv_rows)
            if (!row.lift_failed)
                scores.push_back(row.mutation_score_pct);
        if (!scores.empty())
        {
            std::sort(scores.begin(), scores.end());
            size_t n = scores.size();
            double median = (n % 2 == 0)
                ? (scores[n / 2 - 1] + scores[n / 2]) / 2.0
                : scores[n / 2];
            os << "  Median mutation score:           " << fmt_dbl(median) << "%\n";
        }
    }

    // Per-category aggregate.
    if (!agg_by_category.empty())
    {
        os << "\n--- By Category (aggregate) ---\n";
        constexpr MutationCategory all_cats[] = {
            MutationCategory::ARITHMETIC,       MutationCategory::BITWISE,
            MutationCategory::COMPARISON_NEG,   MutationCategory::COMPARISON_BDRY,
            MutationCategory::OPERAND_SWAP,     MutationCategory::DROP_COMPUTATION,
            MutationCategory::CONSTANT_REPL,    MutationCategory::NEGATE_TRUNC,
        };
        for (auto cat : all_cats)
        {
            auto it = agg_by_category.find(cat);
            if (it == agg_by_category.end() || it->second.second == 0)
                continue;
            auto [k, t] = it->second;
            auto diff = static_difficulty(cat);
            std::string_view diff_name =
                diff == difficulty_t::EASY   ? "EASY"
              : diff == difficulty_t::MEDIUM ? "MEDIUM" : "HARD";
            os << "  " << std::left << std::setw(20) << category_name(cat)
               << "killed " << k << "/" << t
               << "  (" << fmt_dbl(pct(k, t)) << "%)"
               << "  [" << diff_name << "]\n";
        }
    }

    // Per-difficulty aggregate.
    if (!agg_by_difficulty.empty())
    {
        os << "\n--- By Difficulty (aggregate) ---\n";
        constexpr difficulty_t all_diffs[] = {
            difficulty_t::EASY, difficulty_t::MEDIUM, difficulty_t::HARD};
        for (auto d : all_diffs)
        {
            auto it = agg_by_difficulty.find(d);
            if (it == agg_by_difficulty.end() || it->second.second == 0)
                continue;
            auto [k, t] = it->second;
            std::string_view dname =
                d == difficulty_t::EASY   ? "EASY"
              : d == difficulty_t::MEDIUM ? "MEDIUM" : "HARD";
            os << "  " << std::left << std::setw(8) << dname
               << "killed " << k << "/" << t
               << "  (" << fmt_dbl(pct(k, t)) << "%)\n";
        }
    }

    // Per-width aggregate.
    if (!agg_by_width_bits.empty())
    {
        os << "\n--- By Width (aggregate) ---\n";
        constexpr unsigned ordered_widths[] = {64, 32, 16, 8, 1};
        for (unsigned w : ordered_widths)
        {
            auto it = agg_by_width_bits.find(w);
            if (it == agg_by_width_bits.end() || it->second.second == 0)
                continue;
            auto [k, t] = it->second;
            std::string lbl = "i" + std::to_string(w);
            os << "  " << std::left << std::setw(6) << lbl
               << "killed " << k << "/" << t
               << "  (" << fmt_dbl(pct(k, t)) << "%)\n";
        }
        // Any widths not in the canonical list.
        for (const auto &[w, kt] : agg_by_width_bits)
        {
            bool ordered = false;
            for (unsigned ow : ordered_widths)
                if (ow == w) { ordered = true; break; }
            if (ordered || kt.second == 0)
                continue;
            auto [k, t] = kt;
            std::string lbl = "i" + std::to_string(w);
            os << "  " << std::left << std::setw(6) << lbl
               << "killed " << k << "/" << t
               << "  (" << fmt_dbl(pct(k, t)) << "%)  [other]\n";
        }
    }

    // Timing.
    {
        os << "\n--- Timing ---\n";
        double avg_lift = tested > 0
            ? total_lift_ms / static_cast<double>(tested) : 0.0;
        double avg_campaign = tested > 0
            ? total_campaign_ms / static_cast<double>(tested) : 0.0;
        // Per-mutant time = campaign time minus lift time, divided by mutants.
        double per_mutant = total_mutants > 0
            ? (total_campaign_ms - total_lift_ms) / static_cast<double>(total_mutants) : 0.0;
        os << "  Avg lift time per function:     " << fmt_dbl(avg_lift, 2) << " ms\n";
        os << "  Avg campaign time per function: " << fmt_dbl(avg_campaign, 2) << " ms\n";
        os << "  Avg time per mutant tested:     " << fmt_dbl(per_mutant, 2) << " ms\n";
    }

    // Notable functions.
    os << "\n--- Notable Functions ---\n";
    if (!perfect_kills.empty())
    {
        os << "  100% kill score (" << perfect_kills.size() << "):\n";
        for (const auto &s : perfect_kills)
            os << "    " << s << "\n";
    }
    if (!zero_kills.empty())
    {
        os << "  0% kill score, >= 5 mutants (" << zero_kills.size() << "):\n";
        for (const auto &s : zero_kills)
            os << "    " << s << "\n";
    }
    // Top 3 worst-scoring functions (adjusted score, at least 5 mutants).
    {
        std::vector<const MutateRow *> candidates;
        for (const auto &row : csv_rows)
            if (!row.lift_failed && row.total_mutants >= 5)
                candidates.push_back(&row);
        std::sort(candidates.begin(), candidates.end(),
                  [](const MutateRow *a, const MutateRow *b)
                  { return a->adjusted_score_pct < b->adjusted_score_pct; });
        size_t n = std::min<size_t>(3, candidates.size());
        if (n > 0)
        {
            os << "  Worst adjusted score (top " << n << "):\n";
            for (size_t i = 0; i < n; ++i)
            {
                const auto *row = candidates[i];
                os << "    " << row->binary << "::" << row->func
                   << "  adj=" << fmt_dbl(row->adjusted_score_pct) << "%"
                   << "  killed=" << row->killed << "/" << row->total_mutants << "\n";
            }
        }
    }

    // Lift failures.
    if (!lift_error_labels.empty())
    {
        os << "\n--- Lift Failures ---\n";
        for (const auto &e : lift_error_labels)
            os << "  " << e << "\n";
    }

    const char *status =
        exit_code() == 0 ? "PASS" : (exit_code() == 1 ? "WARN" : "ERROR");
    os << "\nExit status: " << status << "\n";
}

void MutateSummary::write_csv(const fs::path &path) const
{
    std::ofstream f(path);
    if (!f)
    {
        errs() << "warning: cannot write mutation CSV to '" << path.string() << "'\n";
        return;
    }
    f << "binary,func,obfuscator,lift_failed,total_enumerated,total_mutants,budget,"
         "killed,survived,equivalent,errors,mutation_score_pct,adjusted_score_pct,"
         "lift_duration_ms,campaign_duration_ms\n";
    for (const auto &row : csv_rows)
    {
        f << row.binary << "," << row.func << "," << row.obfuscator << ","
          << (row.lift_failed ? 1 : 0) << ","
          << row.total_enumerated << "," << row.total_mutants << "," << row.budget << ","
          << row.killed << "," << row.survived << "," << row.equivalent << ","
          << row.errors << ","
          << fmt_dbl(row.mutation_score_pct, 2) << ","
          << fmt_dbl(row.adjusted_score_pct, 2) << ","
          << fmt_dbl(row.lift_duration_ms, 2) << ","
          << fmt_dbl(row.campaign_duration_ms, 2) << "\n";
    }
}

// ── Output ─────────────────────────────────────────────────────────────────────

static void print_function_header(size_t idx, size_t total,
                                  const fs::path &so_path,
                                  const std::string &func_name,
                                  uint64_t rva,
                                  std::ostream *file_os = nullptr)
{
    outs() << "\n--- [" << idx << "/" << total << "] "
           << so_path.filename().string() << " :: " << func_name
           << " @ " << llvm::format_hex(rva, 18) << " ---\n";
    if (file_os)
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%016llx", (unsigned long long)rva);
        *file_os << "\n--- [" << idx << "/" << total << "] "
                 << so_path.filename().string() << " :: " << func_name
                 << " @ " << buf << " ---\n";
    }
}

// detail_os: if non-null, full pipeline output (PipelineReport, DeepDiveResult) is written
// there in addition to the brief lines on outs(). Pass nullptr when per-function report
// files are being written separately via write_function_reports().
// Brief status lines ([STAGE N], [RESULT]) always go to outs() for terminal visibility.
static void print_function_result(const FullPipelineResult &r,
                                  std::ostream *detail_os = &std::cout)
{
    if (r.lift_failed)
    {
        outs() << "  [LIFTING]  FAILED: " << r.lift_error << "\n";
        return;
    }
    outs() << "  [LIFTING]  OK\n";

    if (detail_os)
    {
        if (r.raw_vs_native)
            r.raw_vs_native->print(*detail_os);
        if (r.raw_vs_native_dive)
        {
            *detail_os << "  [DEEP DIVE S1 1/1]\n";
            r.raw_vs_native_dive->print(*detail_os);
        }
        detail_os->flush();
    }

    size_t fails1 = r.raw_vs_native ? r.raw_vs_native->total_failures() : 0;
    outs() << "  [STAGE 1]  " << (fails1 == 0 ? "PASS" : "FAIL")
           << "  (raw lifted IR vs. Unicorn";
    if (fails1 > 0)
        outs() << " \xe2\x80\x94 " << fails1 << " divergence(s)";
    outs() << ")\n";

    if (!r.opt_transform_error.empty())
    {
        outs() << "  [STAGE 2]  ERROR  (O2 transform: " << r.opt_transform_error << ")\n";
    }
    else if (r.opt_vs_raw)
    {
        if (detail_os)
        {
            r.opt_vs_raw->print(*detail_os);
            if (r.opt_vs_raw_dive)
            {
                *detail_os << "  [DEEP DIVE S2 1/1]\n";
                r.opt_vs_raw_dive->print(*detail_os);
            }
            detail_os->flush();
        }
        size_t fails2 = r.opt_vs_raw->total_failures();
        outs() << "  [STAGE 2]  " << (fails2 == 0 ? "PASS" : "FAIL")
               << "  (O2 IR vs. raw lifted IR";
        if (fails2 > 0)
            outs() << " \xe2\x80\x94 " << fails2 << " divergence(s)";
        outs() << ")\n";
    }
    else
    {
        bool s1_passed = r.raw_vs_native && r.raw_vs_native->total_failures() == 0;
        if (s1_passed)
            outs() << "  [STAGE 2]  N/A  (--no-full-pipeline)\n";
        else
            outs() << "  [STAGE 2]  N/A  (Stage 1 failed \xe2\x80\x94 skipped)\n";
    }

    outs() << "  [RESULT]   " << (r.full_pass() ? "PASS" : "FAIL") << "\n";
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// Wrap a single-stage LiftAndVerifyResult into FullPipelineResult for uniform handling.
static FullPipelineResult stage1_only_result(LiftAndVerifyResult &&r)
{
    FullPipelineResult fr;
    fr.lift_stats = std::move(r.lift_stats);
    fr.cfg = std::move(r.cfg);
    fr.lift_failed = r.lift_failed;
    fr.lift_error = std::move(r.lift_error);
    if (!r.lift_failed && r.report)
    {
        fr.raw_vs_native = std::move(r.report);
        fr.raw_vs_native_dive = std::move(r.deep_dive);
    }
    return fr;
}

// Write a per-function DOT file (with Stage 1 overlay) and optionally render it.
static void write_function_dot(const FullPipelineResult &r,
                               const fs::path &out_dir,
                               const std::string &stem,
                               const std::string &func,
                               const std::string &render_fmt)
{
    if (!r.cfg)
        return;

    lifted::visualization::CfgDotOptions cfg_opts;
    cfg_opts.graph_title = stem + "::" + func;
    std::string dot;

    if (r.raw_vs_native)
    {
        lifted::visualization::OverlayData od;
        od.block_hits = &r.raw_vs_native->src_block_hits;
        for (const auto &stg : r.raw_vs_native->stages)
        {
            if (!stg.divergences.empty())
            {
                od.divergence = &stg.divergences[0];
                break;
            }
        }
        lifted::visualization::OverlayOptions oo;
        oo.cfg_opts = cfg_opts;
        dot = lifted::visualization::overlay_to_dot(*r.cfg, od, oo);
    }
    else
    {
        dot = lifted::visualization::cfg_to_dot(*r.cfg, cfg_opts);
    }

    fs::path dot_path = out_dir / (stem + "_" + func + ".dot");
    {
        std::error_code ec;
        llvm::raw_fd_ostream os(dot_path.string(), ec);
        if (ec)
        {
            errs() << "  [WARN] cannot write DOT '" << dot_path.string() << "': " << ec.message() << "\n";
            return;
        }
        os << dot;
    }

    if (!render_fmt.empty())
    {
        fs::path rendered = fs::path(dot_path).replace_extension("." + render_fmt);
        std::string cmd = "dot -T" + render_fmt + " -o " + rendered.string() + " " + dot_path.string();
        if (std::system(cmd.c_str()) != 0)
            errs() << "  [WARN] graphviz render failed for " << dot_path.string() << "\n";
    }
}

// Write three per-function report files into out_dir:
//   <stem>_<func>.lift.report.txt   — lift stats (or failure reason)
//   <stem>_<func>.stage1.report.txt — Stage 1 pipeline report + deep dive
//   <stem>_<func>.stage2.report.txt — Stage 2 pipeline report + deep dive
// Files for stages that were not run are not created.
static void write_function_reports(const FullPipelineResult &r,
                                   const fs::path &out_dir,
                                   const std::string &stem,
                                   const std::string &func)
{
    const std::string prefix = stem + "_" + func;

    // Lift report: always written.
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

    // Stage 1 report: written when Stage 1 ran.
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

    // Stage 2 report: written when Stage 2 ran (not when skipped or errored).
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

// Write a per-function mutation report file to out_dir.
// Filename: <stem>_<func>.mutation.report.txt
static void write_function_mutation_report(const LiftAndMutateResult &r,
                                           const fs::path &out_dir,
                                           const std::string &stem,
                                           const std::string &func)
{
    std::ofstream f(out_dir / (stem + "_" + func + ".mutation.report.txt"));
    if (!f)
    {
        errs() << "  [WARN] cannot write mutation report for " << func << "\n";
        return;
    }
    if (r.lift_failed)
        f << "[LIFTING FAILED] " << r.lift_error << "\n";
    else if (!r.report)
        f << "[NO REPORT]\n";
    else
        r.report->print(f);
}

// ── Subcommand: suite ─────────────────────────────────────────────────────────

static int run_suite_cmd(LLVMContext &ctx)
{
    auto csv_path = resolve_suite_arg(SuiteName);
    if (!csv_path)
    {
        errs() << "suite error: " << toString(csv_path.takeError()) << "\n";
        return 2;
    }

    auto suite = parse_suite_csv(*csv_path);
    if (suite.empty())
    {
        errs() << "suite error: no entries in " << csv_path->string() << "\n";
        return 2;
    }

    std::set<std::string> ignore_set(SuiteIgnore.begin(), SuiteIgnore.end());
    size_t deep_count = static_cast<size_t>(SuiteMaxDeepDives < 0 ? 0 : SuiteMaxDeepDives);
    bool no_full = SuiteNoFullPipeline;
    std::string obf_filter = std::string(SuiteObfuscator);

    auto matches_obf = [&](const std::string &obf) -> bool
    {
        if (obf_filter == "all")
            return true;
        if (obf_filter == "none")
            return obf.empty();
        return obf == obf_filter;
    };

    // Setup output directory.
    std::optional<fs::path> out_dir;
    if (!SuiteOutputDir.empty())
    {
        out_dir = fs::path(std::string(SuiteOutputDir));
        std::error_code ec;
        fs::create_directories(*out_dir, ec);
        if (ec)
        {
            errs() << "suite error: cannot create output-dir '" << out_dir->string()
                   << "': " << ec.message() << "\n";
            return 2;
        }
    }
    std::string render_fmt = std::string(SuiteRenderCfg);
    if (!render_fmt.empty() && !out_dir)
    {
        errs() << "suite error: --render-cfg requires --output-dir\n";
        return 2;
    }

    // Count total functions applying both filters.
    size_t total = 0;
    for (const auto &entry : suite)
    {
        const std::string cstem = target_stem(entry.so_path);
        if (ignore_set.count(cstem))
            continue;
        if (!matches_obf(entry.obfuscator))
            continue;
        auto targets = parse_targets_csv(entry.targets_csv_path);
        for (const auto &t : targets)
            if (!ignore_set.count(cstem + "::" + t.func_name))
                ++total;
    }

    RunSummary summary;
    size_t idx = 0;


    for (const auto &entry : suite)
    {
        std::string stem = target_stem(entry.so_path);
        if (ignore_set.count(stem))
        {
            outs() << "  [SKIPPED] " << entry.so_path.filename().string() << "\n";
            continue;
        }
        if (!matches_obf(entry.obfuscator))
            continue;

        auto targets = parse_targets_csv(entry.targets_csv_path);
        for (const auto &t : targets)
        {
            if (ignore_set.count(stem + "::" + t.func_name))
            {
                outs() << "  [SKIPPED] " << stem << "::" << t.func_name << "\n";
                continue;
            }
            ++idx;
            print_function_header(idx, total, entry.so_path, t.func_name, t.addr);

            bool fatal = false;
            FullPipelineResult fr;

            if (no_full)
            {
                auto r = lift_and_verify_named(ctx, entry.so_path, t.func_name,
                                               t.addr, deep_count, entry.obfuscator);
                if (!r)
                {
                    errs() << "  [FATAL] " << toString(r.takeError()) << "\n";
                    summary.record_fatal(stem + "::" + t.func_name, stem, t.func_name,
                                         entry.obfuscator);
                    fatal = true;
                }
                else
                {
                    fr = stage1_only_result(std::move(*r));
                }
            }
            else
            {
                auto r = lift_and_verify_full_named(ctx, entry.so_path, t.func_name,
                                                    t.addr, deep_count, entry.obfuscator);
                if (!r)
                {
                    errs() << "  [FATAL] " << toString(r.takeError()) << "\n";
                    summary.record_fatal(stem + "::" + t.func_name, stem, t.func_name,
                                         entry.obfuscator);
                    fatal = true;
                }
                else
                {
                    fr = std::move(*r);
                }
            }

            if (fatal)
                continue;

            print_function_result(fr, out_dir ? nullptr : &std::cout);
            summary.record(stem + "::" + t.func_name, fr, stem, t.func_name, entry.obfuscator);
            if (out_dir)
                write_function_dot(fr, *out_dir, stem, t.func_name, render_fmt);
            if (out_dir)
                write_function_reports(fr, *out_dir, stem, t.func_name);
        }
    }

    const std::string suite_label = std::string(SuiteName) + " (obfuscator=" + obf_filter + ")";
    summary.print_summary(suite_label, std::cout);

    if (out_dir)
    {
        fs::path rpt_path = *out_dir / "report.txt";
        std::ofstream rpt(rpt_path);
        if (rpt)
            summary.print_summary(suite_label, rpt);
        else
            errs() << "warning: cannot write '" << rpt_path.string() << "'\n";

        summary.write_csv(*out_dir / "summary.csv");
    }

    return summary.exit_code();
}

// ── Subcommand: target ────────────────────────────────────────────────────────

static int run_target_cmd(LLVMContext &ctx)
{
    auto csv_path = resolve_suite_arg(TargetSuite);
    if (!csv_path)
    {
        errs() << "target error: " << toString(csv_path.takeError()) << "\n";
        return 2;
    }

    auto suite = parse_suite_csv(*csv_path);

    std::optional<SuiteEntry> found;
    for (const auto &entry : suite)
    {
        if (target_stem(entry.so_path) == std::string(TargetName))
        {
            found = entry;
            break;
        }
    }
    if (!found)
    {
        errs() << "target error: no target '" << TargetName
               << "' in suite '" << TargetSuite << "'\n";
        return 2;
    }

    std::set<std::string> ignore_set(TargetIgnore.begin(), TargetIgnore.end());
    size_t deep_count = static_cast<size_t>(TargetMaxDeepDives < 0 ? 0 : TargetMaxDeepDives);
    bool no_full = TargetNoFullPipeline;

    // Setup output directory.
    std::optional<fs::path> out_dir;
    if (!TargetOutputDir.empty())
    {
        out_dir = fs::path(std::string(TargetOutputDir));
        std::error_code ec;
        fs::create_directories(*out_dir, ec);
        if (ec)
        {
            errs() << "target error: cannot create output-dir '" << out_dir->string()
                   << "': " << ec.message() << "\n";
            return 2;
        }
    }
    std::string render_fmt = std::string(TargetRenderCfg);
    if (!render_fmt.empty() && !out_dir)
    {
        errs() << "target error: --render-cfg requires --output-dir\n";
        return 2;
    }

    auto targets = parse_targets_csv(found->targets_csv_path);
    if (targets.empty())
    {
        errs() << "target error: no functions in " << found->targets_csv_path.string() << "\n";
        return 2;
    }

    size_t total = 0;
    for (const auto &t : targets)
        if (!ignore_set.count(t.func_name) &&
            !ignore_set.count(target_stem(found->so_path) + "::" + t.func_name))
            ++total;

    RunSummary summary;
    size_t idx = 0;
    std::string stem = target_stem(found->so_path);


    for (const auto &t : targets)
    {
        if (ignore_set.count(t.func_name) ||
            ignore_set.count(stem + "::" + t.func_name))
        {
            outs() << "  [SKIPPED] " << t.func_name << "\n";
            continue;
        }

        ++idx;
        print_function_header(idx, total, found->so_path, t.func_name, t.addr);

        bool fatal = false;
        FullPipelineResult fr;

        if (no_full)
        {
            auto r = lift_and_verify_named(ctx, found->so_path, t.func_name,
                                           t.addr, deep_count, found->obfuscator);
            if (!r)
            {
                errs() << "  [FATAL] " << toString(r.takeError()) << "\n";
                summary.record_fatal(t.func_name, stem, t.func_name, found->obfuscator);
                fatal = true;
            }
            else
            {
                fr = stage1_only_result(std::move(*r));
            }
        }
        else
        {
            auto r = lift_and_verify_full_named(ctx, found->so_path, t.func_name,
                                                t.addr, deep_count, found->obfuscator);
            if (!r)
            {
                errs() << "  [FATAL] " << toString(r.takeError()) << "\n";
                summary.record_fatal(t.func_name, stem, t.func_name, found->obfuscator);
                fatal = true;
            }
            else
            {
                fr = std::move(*r);
            }
        }

        if (fatal)
            continue;

        print_function_result(fr, out_dir ? nullptr : &std::cout);
        summary.record(t.func_name, fr, stem, t.func_name, found->obfuscator);
        if (out_dir)
            write_function_dot(fr, *out_dir, stem, t.func_name, render_fmt);
            if (out_dir)
                write_function_reports(fr, *out_dir, stem, t.func_name);
    }

    std::string label = std::string(TargetSuite) + " / " + std::string(TargetName);
    summary.print_summary(label, std::cout);

    if (out_dir)
    {
        fs::path rpt_path = *out_dir / "report.txt";
        std::ofstream rpt(rpt_path);
        if (rpt)
            summary.print_summary(label, rpt);
        else
            errs() << "warning: cannot write '" << rpt_path.string() << "'\n";

        summary.write_csv(*out_dir / "summary.csv");
    }

    return summary.exit_code();
}

// ── Subcommand: fn ────────────────────────────────────────────────────────────

static int run_fn_cmd(LLVMContext &ctx)
{
    bool has_binary = !FnBinary.empty();
    bool has_rva = !FnRva.empty();
    bool has_export = !FnExport.empty();
    bool has_suite = !FnSuite.empty();
    bool has_target = !FnTarget.empty();
    bool has_func = !FnFunc.empty();

    size_t deep_count = static_cast<size_t>(FnMaxDeepDives < 0 ? 0 : FnMaxDeepDives);

    fs::path binary_path;
    uint64_t rva = 0;
    std::string func_name;
    std::string fn_obfuscator;

    if (has_binary && has_rva && !has_export && !has_suite)
    {
        // Mode A: --binary + --rva
        binary_path = fs::path(std::string(FnBinary));
        try
        {
            rva = std::stoull(FnRva, nullptr, 16);
        }
        catch (...)
        {
            errs() << "fn error: invalid RVA '" << FnRva << "'\n";
            return 2;
        }
        func_name = FnDisplayName.empty()
                        ? ("sub_" + llvm::utohexstr(rva))
                        : std::string(FnDisplayName);
    }
    else if (has_binary && has_export && !has_rva && !has_suite)
    {
        // Mode B: --binary + --export
        binary_path = fs::path(std::string(FnBinary));
        auto binary = LIEF::Parser::parse(binary_path.string());
        if (!binary)
        {
            errs() << "fn error: failed to parse binary '" << FnBinary << "'\n";
            return 2;
        }
        auto rva_result = lifted::utils::rva_from_export(*binary, FnExport);
        if (!rva_result)
        {
            errs() << "fn error: " << toString(rva_result.takeError()) << "\n";
            return 2;
        }
        rva = *rva_result;
        func_name = FnDisplayName.empty() ? std::string(FnExport) : std::string(FnDisplayName);
    }
    else if (has_suite && has_target && has_func && !has_binary && !has_rva && !has_export)
    {
        // Mode C: --suite + --target + --func
        auto csv_path = resolve_suite_arg(FnSuite);
        if (!csv_path)
        {
            errs() << "fn error: " << toString(csv_path.takeError()) << "\n";
            return 2;
        }

        auto suite = parse_suite_csv(*csv_path);

        std::optional<SuiteEntry> found_entry;
        for (const auto &entry : suite)
        {
            if (target_stem(entry.so_path) == std::string(FnTarget))
            {
                found_entry = entry;
                break;
            }
        }
        if (!found_entry)
        {
            errs() << "fn error: no target '" << FnTarget
                   << "' in suite '" << FnSuite << "'\n";
            return 2;
        }

        auto targets = parse_targets_csv(found_entry->targets_csv_path);

        std::optional<TargetEntry> found_fn;
        for (const auto &t : targets)
        {
            if (t.func_name == std::string(FnFunc))
            {
                found_fn = t;
                break;
            }
        }
        if (!found_fn)
        {
            errs() << "fn error: no function '" << FnFunc
                   << "' in target '" << FnTarget << "'\n";
            return 2;
        }

        binary_path = found_entry->so_path;
        rva = found_fn->addr;
        fn_obfuscator = found_entry->obfuscator;
        func_name = FnDisplayName.empty() ? std::string(FnFunc) : std::string(FnDisplayName);
    }
    else
    {
        errs() << "fn error: specify one of:\n"
               << "  Mode A: --binary <path> --rva <hex>\n"
               << "  Mode B: --binary <path> --export <name>\n"
               << "  Mode C: --suite <name> --target <stem> --func <name>\n";
        return 2;
    }

    // Validate output options before printing the function header.
    std::optional<fs::path> fn_out_dir;
    if (!FnOutputDir.empty())
    {
        fn_out_dir = fs::path(std::string(FnOutputDir));
        std::error_code ec;
        fs::create_directories(*fn_out_dir, ec);
        if (ec)
        {
            errs() << "fn error: cannot create output-dir '" << fn_out_dir->string()
                   << "': " << ec.message() << "\n";
            return 2;
        }
    }
    std::string fn_render_fmt = std::string(FnRenderCfg);
    if (!fn_render_fmt.empty() && !fn_out_dir)
    {
        errs() << "fn error: --render-cfg requires --output-dir\n";
        return 2;
    }

    bool fn_no_full = FnNoFullPipeline;

    print_function_header(1, 1, binary_path, func_name, rva);

    FullPipelineResult fr;
    if (fn_no_full)
    {
        auto result = lift_and_verify_named(ctx, binary_path, func_name, rva,
                                            deep_count, fn_obfuscator);
        if (!result)
        {
            errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
            return 2;
        }
        fr = stage1_only_result(std::move(*result));
    }
    else
    {
        auto result = lift_and_verify_full_named(ctx, binary_path, func_name, rva,
                                                 deep_count, fn_obfuscator);
        if (!result)
        {
            errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
            return 2;
        }
        fr = std::move(*result);
    }

    print_function_result(fr, fn_out_dir ? nullptr : &std::cout);
    if (fn_out_dir)
        write_function_reports(fr, *fn_out_dir, binary_path.stem().string(), func_name);

    if (fn_out_dir)
        write_function_dot(fr, *fn_out_dir, binary_path.stem().string(), func_name, fn_render_fmt);

    if (fr.lift_failed)
        return 2;
    return fr.full_pass() ? 0 : 1;
}

// ── Subcommand: list ───────────────────────────────────────────────────────────────

static int run_list_cmd()
{
    auto print_suite = [](const std::string &suite_name)
    {
        auto csv_path = resolve_suite_name(suite_name);
        if (!csv_path)
        {
            errs() << "  [ERROR] Cannot resolve suite '" << suite_name << "'\n";
            return;
        }
        auto suite = parse_suite_csv(*csv_path);
        outs() << "Suite: " << suite_name << "  (" << suite.size() << " targets)\n";
        for (const auto &entry : suite)
        {
            std::string stem = entry.so_path.stem().string();
            if (stem.starts_with("libeval-"))
                stem = stem.substr(8);
            else if (stem.starts_with("lib"))
                stem = stem.substr(3);
            auto targets = parse_targets_csv(entry.targets_csv_path);
            outs() << "  " << stem << "  (" << targets.size() << " function(s))\n";
            for (const auto &t : targets)
                outs() << "    " << t.func_name
                       << "  @ " << format_hex(t.addr, 10) << "\n";
        }
        outs() << "\n";
    };

    if (!ListSuite.empty())
    {
        print_suite(std::string(ListSuite));
    }
    else
    {
        auto names = known_suite_names();
        if (names.empty())
        {
            errs() << "list error: no known suites (built without CSV paths)\n";
            return 2;
        }
        for (const auto &n : names)
            print_suite(n);
    }
    return 0;
}

// -- Subcommand: graph --------------------------------------------------------

static int run_graph_cmd(LLVMContext &ctx)
{
    // -- Resolve input (replicated from run_fn_cmd) ---------------------------
    bool has_binary = !GraphBinary.empty();
    bool has_rva = !GraphRva.empty();
    bool has_export = !GraphExport.empty();
    bool has_suite = !GraphSuite.empty();
    bool has_target = !GraphTarget.empty();
    bool has_func = !GraphFunc.empty();

    fs::path binary_path;
    uint64_t rva = 0;
    std::string func_name;
    std::string graph_obfuscator;

    if (has_binary && has_rva && !has_export && !has_suite)
    {
        // Mode A: --binary + --rva
        binary_path = fs::path(std::string(GraphBinary));
        try
        {
            rva = std::stoull(GraphRva, nullptr, 16);
        }
        catch (...)
        {
            errs() << "graph error: invalid RVA '" << GraphRva << "'\n";
            return 2;
        }
        func_name = GraphDisplayName.empty()
                        ? ("sub_" + llvm::utohexstr(rva))
                        : std::string(GraphDisplayName);
    }
    else if (has_binary && has_export && !has_rva && !has_suite)
    {
        // Mode B: --binary + --export
        binary_path = fs::path(std::string(GraphBinary));
        auto binary = LIEF::Parser::parse(binary_path.string());
        if (!binary)
        {
            errs() << "graph error: failed to parse binary '" << GraphBinary << "'\n";
            return 2;
        }
        auto rva_result = lifted::utils::rva_from_export(*binary, GraphExport);
        if (!rva_result)
        {
            errs() << "graph error: " << toString(rva_result.takeError()) << "\n";
            return 2;
        }
        rva = *rva_result;
        func_name = GraphDisplayName.empty() ? std::string(GraphExport) : std::string(GraphDisplayName);
    }
    else if (has_suite && has_target && has_func && !has_binary && !has_rva && !has_export)
    {
        // Mode C: --suite + --target + --func
        auto csv_path = resolve_suite_arg(GraphSuite);
        if (!csv_path)
        {
            errs() << "graph error: " << toString(csv_path.takeError()) << "\n";
            return 2;
        }
        auto suite = parse_suite_csv(*csv_path);
        std::optional<SuiteEntry> found_entry;
        for (const auto &entry : suite)
        {
            if (target_stem(entry.so_path) == std::string(GraphTarget))
            {
                found_entry = entry;
                break;
            }
        }
        if (!found_entry)
        {
            errs() << "graph error: no target '" << GraphTarget
                   << "' in suite '" << GraphSuite << "'\n";
            return 2;
        }
        auto targets = parse_targets_csv(found_entry->targets_csv_path);
        std::optional<TargetEntry> found_fn;
        for (const auto &t : targets)
        {
            if (t.func_name == std::string(GraphFunc))
            {
                found_fn = t;
                break;
            }
        }
        if (!found_fn)
        {
            errs() << "graph error: no function '" << GraphFunc
                   << "' in target '" << GraphTarget << "'\n";
            return 2;
        }
        binary_path = found_entry->so_path;
        rva = found_fn->addr;
        graph_obfuscator = found_entry->obfuscator;
        func_name = GraphDisplayName.empty() ? std::string(GraphFunc) : std::string(GraphDisplayName);
    }
    else
    {
        errs() << "graph error: specify one of:\n"
               << "  Mode A: --binary <path> --rva <hex>\n"
               << "  Mode B: --binary <path> --export <name>\n"
               << "  Mode C: --suite <name> --target <stem> --func <name>\n";
        return 2;
    }

    // -- Build CfgDotOptions from flags ---------------------------------------
    lifted::visualization::CfgDotOptions cfg_opts;
    cfg_opts.merge_synthetic = GraphMergeSynthetic;
    cfg_opts.graph_title = func_name + " @ 0x" + llvm::utohexstr(rva);

    // -- Generate DOT string --------------------------------------------------
    std::string dot;

    if (GraphOverlay)
    {
        // Overlay mode: run the full pipeline, then overlay execution data.
        size_t deep_count = static_cast<size_t>(GraphMaxDeepDives < 0 ? 0 : GraphMaxDeepDives);
        auto result = lift_and_verify_named(ctx, binary_path, func_name, rva, deep_count, graph_obfuscator);
        if (!result)
        {
            errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
            return 2;
        }
        if (result->lift_failed)
        {
            errs() << "  [LIFTING] FAILED: " << result->lift_error << "\n";
            return 2;
        }
        if (!result->cfg)
        {
            errs() << "graph error: no CFG snapshot produced (internal error)\n";
            return 2;
        }

        // Build overlay data.
        lifted::visualization::OverlayData od;
        if (result->report)
            od.block_hits = &result->report->src_block_hits;

        // Find the requested divergence (GraphDivergenceIdx).
        const lifted::pipeline::RunOutcome *div_ptr = nullptr;
        if (result->report)
        {
            int want = GraphDivergenceIdx < 0 ? 0 : GraphDivergenceIdx;
            int seen = 0;
            for (const auto &stage : result->report->stages)
            {
                for (const auto &d : stage.divergences)
                {
                    if (seen == want)
                    {
                        div_ptr = &d;
                        break;
                    }
                    ++seen;
                }
                if (div_ptr)
                    break;
            }
        }
        od.divergence = div_ptr;

        // Print pipeline summary to stderr.
        if (result->report)
            result->report->print(std::cerr);

        lifted::visualization::OverlayOptions oo;
        oo.cfg_opts = cfg_opts;
        dot = lifted::visualization::overlay_to_dot(*result->cfg, od, oo);
    }
    else
    {
        // CFG-only mode: lift without running the pipeline.
        auto arch = remill::Arch::Get(ctx, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
        auto binary = LIEF::Parser::parse(binary_path.string());
        if (!binary)
        {
            errs() << "graph error: failed to parse binary '" << binary_path.string() << "'\n";
            return 2;
        }
        lifted::BinaryContext bin_ctx(std::move(binary));
        std::unique_ptr<lifted::lifter::LifterCallbacks> graph_cbs;
        if (graph_obfuscator == "polaris")
        {
            auto cb_cfg = lifted::lifter::polaris_lifter_config_t::from_polaris_linux_binary(bin_ctx.binary());
            graph_cbs = std::make_unique<lifted::lifter::PolarisLifterCallbacks>(std::move(cb_cfg));
        }
        else
        {
            auto cb_cfg = lifted::lifter::standard_lifter_config_t::from_standard_linux_binary(bin_ctx.binary());
            graph_cbs = std::make_unique<lifted::lifter::StandardLifterCallbacks>(std::move(cb_cfg));
        }
        auto lifter_or = lifted::lifter::Lifter::create(arch.get(), bin_ctx, graph_cbs.get());
        if (!lifter_or)
        {
            errs() << "graph error: " << toString(lifter_or.takeError()) << "\n";
            return 2;
        }
        auto entry_ann = std::make_unique<lifted::fnc_annotation_t>();
        entry_ann->cc = &lifted::abi::AllRegistersCC::get();
        lifted::annotation_id_t entry_annotation_id = bin_ctx.add_annotation(std::move(entry_ann));
        auto lift_result = (*lifter_or).lift(rva, entry_annotation_id, {.instrument_bb_entry = false});
        if (!lift_result)
        {
            errs() << "graph error: " << toString(lift_result.takeError()) << "\n";
            return 2;
        }
        auto snapshot = lifted::visualization::make_cfg_snapshot(*lift_result, bin_ctx, rva, func_name);
        dot = lifted::visualization::cfg_to_dot(snapshot, cfg_opts);
    }

    // -- Write or render output -----------------------------------------------
    std::string dot_path;
    bool render = !GraphRender.empty();

    if (!GraphOutput.empty())
    {
        dot_path = std::string(GraphOutput);
    }
    else if (render)
    {
        // Default DOT file name when rendering.
        dot_path = GraphOverlay ? "overlay.dot" : "cfg.dot";
    }

    if (!dot_path.empty())
    {
        // Write DOT to file.
        std::error_code ec;
        raw_fd_ostream os(dot_path, ec);
        if (ec)
        {
            errs() << "graph error: cannot open '" << dot_path << "': " << ec.message() << "\n";
            return 2;
        }
        os << dot;
    }
    else
    {
        // Write DOT to stdout.
        outs() << dot;
    }

    // Render via graphviz if requested.
    if (render)
    {
        const std::string &fmt = GraphRender;
        // Derive rendered output path: same base as dot_path but with .fmt extension.
        std::string render_path;
        {
            fs::path dp(dot_path);
            render_path = dp.replace_extension("." + fmt).string();
        }
        std::string cmd = "dot -T" + fmt + " -o " + render_path + " " + dot_path;
        int rc = std::system(cmd.c_str());
        if (rc != 0)
        {
            errs() << "graph warning: graphviz 'dot' returned " << rc
                   << "; is graphviz installed?\n";
        }
        else
        {
            errs() << "Rendered: " << render_path << "\n";
        }
    }

    return 0;
}

// ── Subcommand: mutate ───────────────────────────────────────────────────────

// Parse a category name string to MutationCategory.  Returns nullopt for unknown.
static std::optional<MutationCategory> parse_category(const std::string &s)
{
    if (s == "arithmetic" || s == "ARITHMETIC")
        return MutationCategory::ARITHMETIC;
    if (s == "bitwise" || s == "BITWISE")
        return MutationCategory::BITWISE;
    if (s == "comparison_neg" || s == "COMPARISON_NEG")
        return MutationCategory::COMPARISON_NEG;
    if (s == "comparison_bdry" || s == "COMPARISON_BDRY")
        return MutationCategory::COMPARISON_BDRY;
    if (s == "operand_swap" || s == "OPERAND_SWAP")
        return MutationCategory::OPERAND_SWAP;
    if (s == "drop_computation" || s == "DROP_COMPUTATION")
        return MutationCategory::DROP_COMPUTATION;
    if (s == "constant_repl" || s == "CONSTANT_REPL")
        return MutationCategory::CONSTANT_REPL;
    if (s == "negate_trunc" || s == "NEGATE_TRUNC")
        return MutationCategory::NEGATE_TRUNC;
    return std::nullopt;
}

static int run_mutate_cmd(LLVMContext &ctx)
{
    bool has_binary = !MutateBinary.empty();
    bool has_rva    = !MutateRva.empty();
    bool has_export = !MutateExport.empty();
    bool has_suite  = !MutateSuite.empty();
    bool has_target = !MutateTarget.empty();
    bool has_func   = !MutateFunc.empty();

    // Build campaign config (shared by all modes).
    MutationCampaign::Config cfg;
    cfg.budget = static_cast<size_t>(MutateBudget < 0 ? 200 : MutateBudget);
    try
    {
        cfg.seed = std::stoull(MutateSeed, nullptr, 16);
    }
    catch (...)
    {
        errs() << "mutate error: invalid seed '" << MutateSeed << "'\n";
        return 2;
    }

    // Parse category filter (shared by all modes).
    for (const auto &cat_str : MutateCategories)
    {
        auto cat = parse_category(cat_str);
        if (!cat)
        {
            errs() << "mutate error: unknown category '" << cat_str
                   << "'; valid: arithmetic, bitwise, comparison_neg, comparison_bdry,"
                   << " operand_swap, drop_computation, constant_repl, negate_trunc\n";
            return 2;
        }
        cfg.filter_categories.push_back(*cat);
    }

    // ── Mode D: --suite [--target] without --func ────────────────────────────
    //   Run campaign on all functions in the suite (optionally filtered to one target).
    if (has_suite && !has_func && !has_binary && !has_rva && !has_export)
    {
        auto csv_path = resolve_suite_arg(MutateSuite);
        if (!csv_path)
        {
            errs() << "mutate error: " << toString(csv_path.takeError()) << "\n";
            return 2;
        }
        auto suite = parse_suite_csv(*csv_path);
        if (suite.empty())
        {
            errs() << "mutate error: no entries in " << csv_path->string() << "\n";
            return 2;
        }

        std::string obf_filter = std::string(MutateObfuscator);
        auto matches_obf = [&](const std::string &obf) -> bool
        {
            if (obf_filter == "all")  return true;
            if (obf_filter == "none") return obf.empty();
            return obf == obf_filter;
        };
        std::set<std::string> ignore_set(MutateIgnore.begin(), MutateIgnore.end());

        // Setup output directory.
        std::optional<fs::path> out_dir;
        if (!MutateOutputDir.empty())
        {
            out_dir = fs::path(std::string(MutateOutputDir));
            std::error_code ec;
            fs::create_directories(*out_dir, ec);
            if (ec)
            {
                errs() << "mutate error: cannot create output-dir '"
                       << out_dir->string() << "': " << ec.message() << "\n";
                return 2;
            }
        }

        // Collect matching (entry, function) work items.
        struct WorkItem { const SuiteEntry *entry; TargetEntry target; };
        std::vector<WorkItem> work;
        for (const auto &entry : suite)
        {
            std::string stem = target_stem(entry.so_path);
            if (ignore_set.count(stem))
                continue;
            if (!matches_obf(entry.obfuscator))
                continue;
            if (has_target && stem != std::string(MutateTarget))
                continue;
            auto targets = parse_targets_csv(entry.targets_csv_path);
            for (const auto &t : targets)
                if (!ignore_set.count(stem + "::" + t.func_name))
                    work.push_back({&entry, t});
        }
        if (work.empty())
        {
            errs() << "mutate error: no matching functions after applying filters\n";
            return 2;
        }

        MutateSummary summary;
        size_t idx = 0;

        for (const auto &wi : work)
        {
            ++idx;
            const std::string stem     = target_stem(wi.entry->so_path);
            const std::string &func    = wi.target.func_name;
            const uint64_t     func_rva = wi.target.addr;

            outs() << "\n--- [MUTATE " << idx << "/" << work.size() << "] "
                   << wi.entry->so_path.filename().string()
                   << " :: " << func
                   << " @ " << llvm::format_hex(func_rva, 18) << " ---\n";
            outs() << "Budget: " << cfg.budget
                   << "  Seed: 0x" << llvm::utohexstr(cfg.seed) << "\n";

            const std::string label = stem + "::" + func;
            auto result = lift_and_mutate_named(ctx, wi.entry->so_path, func, func_rva, cfg);
            if (!result)
            {
                errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
                // Treat fatal infrastructure errors as lift failures.
                LiftAndMutateResult fail_r;
                fail_r.lift_failed = true;
                fail_r.lift_error  = "[fatal infrastructure error]";
                summary.record(label, fail_r, stem, func, wi.entry->obfuscator);
                continue;
            }

            if (out_dir)
                write_function_mutation_report(*result, *out_dir, stem, func);

            summary.record(label, *result, stem, func, wi.entry->obfuscator);

            if (result->lift_failed)
                outs() << "  [LIFT FAIL] " << result->lift_error << "\n";
            else if (result->report)
                outs() << "  [KILL%: "
                       << fmt_dbl(result->report->mutation_score() * 100.0)
                       << "%  adj: "
                       << fmt_dbl(result->report->adjusted_score() * 100.0)
                       << "%]\n";
        }

        const std::string suite_label =
            std::string(MutateSuite)
            + " (obfuscator=" + obf_filter
            + ", budget=" + std::to_string(cfg.budget) + ")";
        summary.print_summary(suite_label, std::cout);

        if (out_dir)
        {
            fs::path rpt_path = *out_dir / "report.txt";
            std::ofstream rpt(rpt_path);
            if (rpt)
                summary.print_summary(suite_label, rpt);
            else
                errs() << "warning: cannot write '" << rpt_path.string() << "'\n";
            summary.write_csv(*out_dir / "summary.csv");
        }

        return summary.exit_code();
    }

    // ── Modes A/B/C: single function ─────────────────────────────────────────
    fs::path binary_path;
    uint64_t    rva       = 0;
    std::string func_name;

    if (has_binary && has_rva && !has_export && !has_suite)
    {
        // Mode A: --binary + --rva
        binary_path = fs::path(std::string(MutateBinary));
        try
        {
            rva = std::stoull(MutateRva, nullptr, 16);
        }
        catch (...)
        {
            errs() << "mutate error: invalid RVA '" << MutateRva << "'\n";
            return 2;
        }
        func_name = "sub_" + llvm::utohexstr(rva);
    }
    else if (has_binary && has_export && !has_rva && !has_suite)
    {
        // Mode B: --binary + --export
        binary_path = fs::path(std::string(MutateBinary));
        auto binary = LIEF::Parser::parse(binary_path.string());
        if (!binary)
        {
            errs() << "mutate error: failed to parse binary\n";
            return 2;
        }
        auto rva_result = lifted::utils::rva_from_export(*binary, MutateExport);
        if (!rva_result)
        {
            errs() << "mutate error: " << toString(rva_result.takeError()) << "\n";
            return 2;
        }
        rva = *rva_result;
        func_name = std::string(MutateExport);
    }
    else if (has_suite && has_target && has_func && !has_binary && !has_rva && !has_export)
    {
        // Mode C: --suite + --target + --func
        auto csv_path = resolve_suite_arg(MutateSuite);
        if (!csv_path)
        {
            errs() << "mutate error: " << toString(csv_path.takeError()) << "\n";
            return 2;
        }
        auto suite = parse_suite_csv(*csv_path);
        std::optional<SuiteEntry> found_entry;
        for (const auto &entry : suite)
            if (target_stem(entry.so_path) == std::string(MutateTarget))
            {
                found_entry = entry;
                break;
            }
        if (!found_entry)
        {
            errs() << "mutate error: no target '" << MutateTarget
                   << "' in suite '" << MutateSuite << "'\n";
            return 2;
        }
        auto targets = parse_targets_csv(found_entry->targets_csv_path);
        std::optional<TargetEntry> found_fn;
        for (const auto &t : targets)
            if (t.func_name == std::string(MutateFunc))
            {
                found_fn = t;
                break;
            }
        if (!found_fn)
        {
            errs() << "mutate error: no function '" << MutateFunc
                   << "' in target '" << MutateTarget << "'\n";
            return 2;
        }
        binary_path = found_entry->so_path;
        rva         = found_fn->addr;
        func_name   = std::string(MutateFunc);
    }
    else
    {
        errs() << "mutate error: specify one of:\n"
               << "  Mode A: --binary <path> --rva <hex>\n"
               << "  Mode B: --binary <path> --export <name>\n"
               << "  Mode C: --suite <name> --target <stem> --func <name>\n"
               << "  Mode D: --suite <name> [--target <stem>]  (no --func, runs all)\n";
        return 2;
    }

    // Setup output directory for single-function modes.
    std::optional<fs::path> fn_out_dir;
    if (!MutateOutputDir.empty())
    {
        fn_out_dir = fs::path(std::string(MutateOutputDir));
        std::error_code ec;
        fs::create_directories(*fn_out_dir, ec);
        if (ec)
        {
            errs() << "mutate error: cannot create output-dir '"
                   << fn_out_dir->string() << "': " << ec.message() << "\n";
            return 2;
        }
    }

    outs() << "\n--- [MUTATE] " << binary_path.filename().string()
           << " :: " << func_name
           << " @ " << llvm::format_hex(rva, 18) << " ---\n";
    outs() << "Budget: " << cfg.budget << "  Seed: 0x" << llvm::utohexstr(cfg.seed) << "\n";

    auto result = lift_and_mutate_named(ctx, binary_path, func_name, rva, cfg);
    if (!result)
    {
        errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
        return 2;
    }

    if (result->lift_failed)
    {
        errs() << "  [ERROR] " << result->lift_error << "\n";
        if (fn_out_dir)
            write_function_mutation_report(*result, *fn_out_dir,
                                           binary_path.stem().string(), func_name);
        return 2;
    }

    // Always print full detail to stdout for single-function modes.
    if (result->report)
        result->report->print(std::cout);

    // Write output-dir files when requested.
    if (fn_out_dir)
    {
        write_function_mutation_report(*result, *fn_out_dir,
                                       binary_path.stem().string(), func_name);
        // One-row summary + report.txt for the single function.
        MutateSummary single_summary;
        const std::string label =
            binary_path.stem().string() + "::" + func_name;
        single_summary.record(label, *result,
                              binary_path.stem().string(), func_name, "");
        single_summary.write_csv(*fn_out_dir / "summary.csv");
        const std::string fn_label =
            func_name + " (" + binary_path.filename().string() + ")";
        fs::path rpt_path = *fn_out_dir / "report.txt";
        std::ofstream rpt(rpt_path);
        if (rpt)
            single_summary.print_summary(fn_label, rpt);
        else
            errs() << "warning: cannot write '" << rpt_path.string() << "'\n";
    }

    return 0;
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char **argv)
{
    FLAGS_minloglevel = 1;
    google::InitGoogleLogging(argv[0]);

    InitLLVM X(argc, argv);
    cl::HideUnrelatedOptions(LiftedCLICategory);
    cl::ParseCommandLineOptions(argc, argv, "lifted-cli — lifting & verification CLI\n");

    LLVMContext ctx;

    if (ListCmd)
        return run_list_cmd();
    if (SuiteCmd)
        return run_suite_cmd(ctx);
    if (TargetCmd)
        return run_target_cmd(ctx);
    if (FnCmd)
        return run_fn_cmd(ctx);
    if (GraphCmd)
        return run_graph_cmd(ctx);
    if (MutateCmd)
        return run_mutate_cmd(ctx);

    cl::PrintHelpMessage();
    return 2;
}
