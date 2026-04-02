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
#include "campaign_reporting.hpp"
#include "mutation_campaign.hpp"
#include "suite.hpp"
#include "utils.hpp"

#include "compat/lief_compat.hpp"

#include "visualization/cfg_dot.hpp"
#include "visualization/pipeline_overlay.hpp"
#include <algorithm>
#include <cstdio> // snprintf
#include <filesystem>
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

static std::string fmt_dbl(double v, int precision = 1)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%.*f", precision, v);
    return buf;
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
        outs() << " — " << fails1 << " divergence(s)";
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
            outs() << " — " << fails2 << " divergence(s)";
        outs() << ")\n";
    }
    else
    {
        bool s1_passed = r.raw_vs_native && r.raw_vs_native->total_failures() == 0;
        if (s1_passed)
            outs() << "  [STAGE 2]  N/A  (--no-full-pipeline)\n";
        else
            outs() << "  [STAGE 2]  N/A  (Stage 1 failed — skipped)\n";
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
            {
                write_function_dot(fr, *out_dir, stem, t.func_name, render_fmt);
                write_function_reports(fr, *out_dir, stem, t.func_name);
            }
        }
    }

    const std::string suite_label = std::string(SuiteName) + " (obfuscator=" + obf_filter + ")";
    summary.print_summary(suite_label, std::cout);

    if (out_dir)
    {
        write_summary_artifacts(summary, suite_label, *out_dir);
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
        {
            write_function_dot(fr, *out_dir, stem, t.func_name, render_fmt);
            write_function_reports(fr, *out_dir, stem, t.func_name);
        }
    }

    std::string label = std::string(TargetSuite) + " / " + std::string(TargetName);
    summary.print_summary(label, std::cout);

    if (out_dir)
    {
        write_summary_artifacts(summary, label, *out_dir);
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

    MutationCampaignConfig cfg;
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

    auto build_eval_config = [&](std::string_view obfuscator)
    {
        EvaluationConfig eval_cfg;
        eval_cfg.deep_dive_count = 1;
        eval_cfg.obfuscator = std::string(obfuscator);
        eval_cfg.run_raw_vs_native = true;
        eval_cfg.run_opt_vs_raw = true;
        eval_cfg.run_eg3_strict = true;
        eval_cfg.run_eg3_relaxed = true;
        eval_cfg.run_mutation = true;
        eval_cfg.mutation_config = cfg;
        return eval_cfg;
    };

    auto mutation_phase_failed = [](const MutationPhaseResult &mutation)
    {
        return mutation.status == MutationPhaseStatus::ERROR ||
               mutation.status == MutationPhaseStatus::SKIPPED;
    };

    auto print_profile_mutation_status = [](std::string_view label, const Eg3ProfileResult &profile)
    {
        outs() << "  [" << label << " / "
               << pipeline_checkpoint_profile_name(profile.profile) << "] ";
        if (profile.mutation.report)
        {
            outs() << "KILL%: "
                   << fmt_dbl(profile.mutation.report->mutation_score() * 100.0)
                   << "%  adj: "
                   << fmt_dbl(profile.mutation.report->adjusted_score() * 100.0)
                   << "%\n";
            return;
        }
        if (profile.mutation.status == MutationPhaseStatus::ERROR)
        {
            outs() << "ERROR: " << profile.mutation.error << "\n";
            return;
        }
        outs() << "SKIPPED: " << profile.mutation.skip_reason << "\n";
    };

    auto print_mutation_status = [&](const EvaluatedFunction &entry)
    {
        if (entry.record.lift_failed)
        {
            outs() << "  [LIFT FAIL] " << entry.record.lift_error << "\n";
            return;
        }
        print_profile_mutation_status("strict", entry.record.eg3_strict);
        print_profile_mutation_status("relaxed", entry.record.eg3_relaxed);
    };

    auto result_exit_code = [&](const std::vector<EvaluatedFunction> &results)
    {
        bool any_failure = false;
        for (const auto &entry : results)
        {
            if (entry.record.lift_failed)
            {
                any_failure = true;
                continue;
            }
            const auto phase_failed = [](const VerificationPhaseResult &phase)
            {
                return phase.status == PhaseStatus::FAIL || phase.status == PhaseStatus::ERROR;
            };
            if (phase_failed(entry.record.raw_vs_native) ||
                phase_failed(entry.record.opt_vs_raw) ||
                phase_failed(entry.record.eg3_strict.selftest) ||
                phase_failed(entry.record.eg3_relaxed.selftest) ||
                mutation_phase_failed(entry.record.eg3_strict.mutation) ||
                mutation_phase_failed(entry.record.eg3_relaxed.mutation))
            {
                any_failure = true;
            }
        }
        return any_failure ? 1 : 0;
    };

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
            if (obf_filter == "all")
                return true;
            if (obf_filter == "none")
                return obf.empty();
            return obf == obf_filter;
        };
        std::set<std::string> ignore_set(MutateIgnore.begin(), MutateIgnore.end());

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

        std::vector<EvaluatedFunction> results;
        results.reserve(work.size());

        size_t idx = 0;
        for (const auto &wi : work)
        {
            ++idx;
            const std::string stem = target_stem(wi.entry->so_path);
            const std::string &func = wi.target.func_name;
            const uint64_t func_rva = wi.target.addr;

            outs() << "\n--- [MUTATE " << idx << "/" << work.size() << "] "
                   << wi.entry->so_path.filename().string()
                   << " :: " << func
                   << " @ " << llvm::format_hex(func_rva, 18) << " ---\n";
            outs() << "Budget: " << cfg.budget
                   << "  Seed: 0x" << llvm::utohexstr(cfg.seed) << "\n";

            auto record_or = run_evaluation_named(
                ctx, wi.entry->so_path, func, func_rva, build_eval_config(wi.entry->obfuscator));
            if (!record_or)
            {
                errs() << "  [FATAL] " << toString(record_or.takeError()) << "\n";
                return 2;
            }

            results.push_back(EvaluatedFunction{
                .suite = std::string(MutateSuite),
                .binary = stem,
                .func = func,
                .obfuscator = wi.entry->obfuscator,
                .record = std::move(*record_or),
            });
            print_mutation_status(results.back());

            if (out_dir)
                write_function_reports(results.back(), *out_dir);
        }

        const std::string suite_label =
            std::string(MutateSuite)
            + " (obfuscator=" + obf_filter
            + ", budget=" + std::to_string(cfg.budget) + ")";
        if (out_dir)
            write_campaign_artifacts(suite_label, results, *out_dir);
        return result_exit_code(results);
    }

    fs::path binary_path;
    uint64_t rva = 0;
    std::string func_name;
    std::string suite_label;

    if (has_binary && has_rva && !has_export && !has_suite)
    {
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
        suite_label = binary_path.filename().string();
    }
    else if (has_binary && has_export && !has_rva && !has_suite)
    {
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
        suite_label = binary_path.filename().string();
    }
    else if (has_suite && has_target && has_func && !has_binary && !has_rva && !has_export)
    {
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
        rva = found_fn->addr;
        func_name = std::string(MutateFunc);
        suite_label = std::string(MutateSuite);
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

    auto record_or = run_evaluation_named(ctx, binary_path, func_name, rva, build_eval_config(""));
    if (!record_or)
    {
        errs() << "  [FATAL] " << toString(record_or.takeError()) << "\n";
        return 2;
    }

    std::vector<EvaluatedFunction> results;
    results.push_back(EvaluatedFunction{
        .suite = suite_label,
        .binary = binary_path.stem().string(),
        .func = func_name,
        .obfuscator = "",
        .record = std::move(*record_or),
    });
    print_mutation_status(results.back());

    if (fn_out_dir)
    {
        write_function_reports(results.back(), *fn_out_dir);
        const std::string fn_label = func_name + " (" + binary_path.filename().string() + ")";
        write_campaign_artifacts(fn_label, results, *fn_out_dir);
    }

    return result_exit_code(results);
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
