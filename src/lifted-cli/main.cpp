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
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include "suite.hpp"
#include "eval_pipeline.hpp"
#include "utils.hpp"

#include "compat/lief_compat.hpp"

#include <filesystem>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include "visualization/cfg_dot.hpp"
#include "visualization/pipeline_overlay.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"

namespace fs = std::filesystem;
using namespace llvm;
using namespace lifted::eval;

// ── Subcommands ────────────────────────────────────────────────────────────────

// Hide LLVM's internal options (debug, stats, etc.) from --help output.
// Subcommand descriptions are not options and survive this filter.
static cl::OptionCategory LiftedCLICategory("lifted-cli options");
static cl::SubCommand ListCmd("list",   "List suites, targets and functions");
static cl::SubCommand SuiteCmd("suite",  "Run all targets in a named suite");
static cl::SubCommand TargetCmd("target", "Run all functions in one suite target");
static cl::SubCommand FnCmd("fn",       "Run a single function");
static cl::SubCommand GraphCmd("graph", "Generate CFG DOT output for a single function");
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

// ── Run summary ────────────────────────────────────────────────────────────────

struct RunSummary
{
    size_t tested = 0;
    size_t pass = 0;
    size_t fail = 0;
    size_t errors = 0;
    std::vector<std::string> failing;

    // Record the outcome of one function run.
    void record(const std::string &label, const LiftAndVerifyResult &r)
    {
        ++tested;
        if (r.lift_failed)
        {
            ++errors;
            failing.push_back(label + " [lift error]");
        }
        else
        {
            bool any_fail = r.report && r.report->total_failures() > 0;
            if (any_fail)
            {
                ++fail;
                failing.push_back(label);
            }
            else
            {
                ++pass;
            }
        }
    }

    // Record a fatal llvm::Error (binary parse / pipeline error).
    void record_fatal(const std::string &label)
    {
        ++tested;
        ++errors;
        failing.push_back(label + " [fatal]");
    }

    int exit_code() const
    {
        // Nothing ran and there were errors -> truly fatal.
        if (tested == 0 && errors > 0)
            return 2;
        return fail > 0 ? 1 : 0;
    }

    void print_summary(const std::string &suite_label) const
    {
        outs() << "\n=== SUITE SUMMARY: " << suite_label << " ===\n";
        outs() << "  Tested:   " << tested << "\n";

        double pass_pct = tested > 0 ? 100.0 * static_cast<double>(pass) / static_cast<double>(tested) : 0.0;
        double fail_pct = tested > 0 ? 100.0 * static_cast<double>(fail) / static_cast<double>(tested) : 0.0;

        outs() << "  PASS:     " << pass << "  (" << llvm::format("%.1f", pass_pct) << "%)\n";
        outs() << "  FAIL:     " << fail << "  (" << llvm::format("%.1f", fail_pct) << "%)\n";
        outs() << "  ERRORS:   " << errors << "\n";

        if (!failing.empty())
        {
            outs() << "  Failures:";
            for (const auto &f : failing)
                outs() << " " << f;
            outs() << "\n";
        }

        const char *status = exit_code() == 0 ? "PASS" : (exit_code() == 1 ? "FAIL" : "ERROR");
        outs() << "Exit status: " << status << "\n";
    }
};

// ── Output ─────────────────────────────────────────────────────────────────────

static void print_function_header(size_t idx, size_t total,
                                  const fs::path &so_path,
                                  const std::string &func_name,
                                  uint64_t rva)
{
    outs() << "\n--- [" << idx << "/" << total << "] "
           << so_path.filename().string() << " :: " << func_name
           << " @ " << llvm::format_hex(rva, 18) << " ---\n";
}

static void print_function_result(const LiftAndVerifyResult &r)
{
    if (r.lift_failed)
    {
        outs() << "  [LIFTING]  FAILED: " << r.lift_error << "\n";
        return;
    }

    outs() << "  [LIFTING]  OK\n";

    if (r.report)
        r.report->print(std::cout);

    if (r.deep_dive)
    {
        outs() << "  [DEEP DIVE 1/1]\n";
        r.deep_dive->print(std::cout);
    }

    bool any_fail = r.report && r.report->total_failures() > 0;
    outs() << "  [RESULT]   " << (any_fail ? "FAIL" : "PASS");
    if (any_fail)
        outs() << "  (" << r.report->total_failures() << " divergence(s))";
    outs() << "\n";
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

    // Count total functions (excluding ignored targets).
    size_t total = 0;
    for (const auto &entry : suite)
    {
        if (ignore_set.count(target_stem(entry.so_path)))
            continue;
        auto targets = parse_targets_csv(entry.targets_csv_path);
        total += targets.size();
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

        auto targets = parse_targets_csv(entry.targets_csv_path);
        for (const auto &t : targets)
        {
            ++idx;
            print_function_header(idx, total, entry.so_path, t.func_name, t.addr);

            auto result = lift_and_verify_named(ctx, entry.so_path, t.func_name, t.addr, deep_count);
            if (!result)
            {
                errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
                summary.record_fatal(stem + "::" + t.func_name);
                continue;
            }

            print_function_result(*result);
            summary.record(stem + "::" + t.func_name, *result);
        }
    }

    summary.print_summary(SuiteName);
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

    // Locate the matching target entry.
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

    auto targets = parse_targets_csv(found->targets_csv_path);
    if (targets.empty())
    {
        errs() << "target error: no functions in "
               << found->targets_csv_path.string() << "\n";
        return 2;
    }

    size_t total = 0;
    for (const auto &t : targets)
        if (!ignore_set.count(t.func_name))
            ++total;

    RunSummary summary;
    size_t idx = 0;

    for (const auto &t : targets)
    {
        if (ignore_set.count(t.func_name))
        {
            outs() << "  [SKIPPED] " << t.func_name << "\n";
            continue;
        }

        ++idx;
        print_function_header(idx, total, found->so_path, t.func_name, t.addr);

        auto result = lift_and_verify_named(ctx, found->so_path, t.func_name, t.addr, deep_count);
        if (!result)
        {
            errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
            summary.record_fatal(t.func_name);
            continue;
        }

        print_function_result(*result);
        summary.record(t.func_name, *result);
    }

    std::string label = std::string(TargetSuite) + " / " + std::string(TargetName);
    summary.print_summary(label);
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

    print_function_header(1, 1, binary_path, func_name, rva);

    auto result = lift_and_verify_named(ctx, binary_path, func_name, rva, deep_count);
    if (!result)
    {
        errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
        return 2;
    }

    print_function_result(*result);

    if (result->lift_failed)
        return 2;
    return (result->report && result->report->total_failures() > 0) ? 1 : 0;
}

// ── Subcommand: list ───────────────────────────────────────────────────────────────

static int run_list_cmd()
{
    auto print_suite = [](const std::string &suite_name) {
        auto csv_path = resolve_suite_name(suite_name);
        if (!csv_path) {
            errs() << "  [ERROR] Cannot resolve suite '" << suite_name << "'\n";
            return;
        }
        auto suite = parse_suite_csv(*csv_path);
        outs() << "Suite: " << suite_name << "  (" << suite.size() << " targets)\n";
        for (const auto &entry : suite) {
            std::string stem = entry.so_path.stem().string();
            if (stem.starts_with("libeval-")) stem = stem.substr(8);
            else if (stem.starts_with("lib")) stem = stem.substr(3);
            auto targets = parse_targets_csv(entry.targets_csv_path);
            outs() << "  " << stem << "  (" << targets.size() << " function(s))\n";
            for (const auto &t : targets)
                outs() << "    " << t.func_name
                       << "  @ " << format_hex(t.addr, 10) << "\n";
        }
        outs() << "\n";
    };

    if (!ListSuite.empty()) {
        print_suite(std::string(ListSuite));
    } else {
        auto names = known_suite_names();
        if (names.empty()) {
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
    bool has_rva    = !GraphRva.empty();
    bool has_export = !GraphExport.empty();
    bool has_suite  = !GraphSuite.empty();
    bool has_target = !GraphTarget.empty();
    bool has_func   = !GraphFunc.empty();

    fs::path    binary_path;
    uint64_t    rva = 0;
    std::string func_name;

    if (has_binary && has_rva && !has_export && !has_suite) {
        // Mode A: --binary + --rva
        binary_path = fs::path(std::string(GraphBinary));
        try {
            rva = std::stoull(GraphRva, nullptr, 16);
        } catch (...) {
            errs() << "graph error: invalid RVA '" << GraphRva << "'\n";
            return 2;
        }
        func_name = GraphDisplayName.empty()
                        ? ("sub_" + llvm::utohexstr(rva))
                        : std::string(GraphDisplayName);
    } else if (has_binary && has_export && !has_rva && !has_suite) {
        // Mode B: --binary + --export
        binary_path = fs::path(std::string(GraphBinary));
        auto binary = LIEF::Parser::parse(binary_path.string());
        if (!binary) {
            errs() << "graph error: failed to parse binary '" << GraphBinary << "'\n";
            return 2;
        }
        auto rva_result = lifted::utils::rva_from_export(*binary, GraphExport);
        if (!rva_result) {
            errs() << "graph error: " << toString(rva_result.takeError()) << "\n";
            return 2;
        }
        rva = *rva_result;
        func_name = GraphDisplayName.empty() ? std::string(GraphExport) : std::string(GraphDisplayName);
    } else if (has_suite && has_target && has_func && !has_binary && !has_rva && !has_export) {
        // Mode C: --suite + --target + --func
        auto csv_path = resolve_suite_arg(GraphSuite);
        if (!csv_path) {
            errs() << "graph error: " << toString(csv_path.takeError()) << "\n";
            return 2;
        }
        auto suite = parse_suite_csv(*csv_path);
        std::optional<SuiteEntry> found_entry;
        for (const auto &entry : suite) {
            if (target_stem(entry.so_path) == std::string(GraphTarget)) {
                found_entry = entry;
                break;
            }
        }
        if (!found_entry) {
            errs() << "graph error: no target '" << GraphTarget
                   << "' in suite '" << GraphSuite << "'\n";
            return 2;
        }
        auto targets = parse_targets_csv(found_entry->targets_csv_path);
        std::optional<TargetEntry> found_fn;
        for (const auto &t : targets) {
            if (t.func_name == std::string(GraphFunc)) {
                found_fn = t;
                break;
            }
        }
        if (!found_fn) {
            errs() << "graph error: no function '" << GraphFunc
                   << "' in target '" << GraphTarget << "'\n";
            return 2;
        }
        binary_path = found_entry->so_path;
        rva         = found_fn->addr;
        func_name   = GraphDisplayName.empty() ? std::string(GraphFunc) : std::string(GraphDisplayName);
    } else {
        errs() << "graph error: specify one of:\n"
               << "  Mode A: --binary <path> --rva <hex>\n"
               << "  Mode B: --binary <path> --export <name>\n"
               << "  Mode C: --suite <name> --target <stem> --func <name>\n";
        return 2;
    }

    // -- Build CfgDotOptions from flags ---------------------------------------
    lifted::visualization::CfgDotOptions cfg_opts;
    cfg_opts.merge_synthetic = GraphMergeSynthetic;
    cfg_opts.graph_title     = func_name + " @ 0x" + llvm::utohexstr(rva);

    // -- Generate DOT string --------------------------------------------------
    std::string dot;

    if (GraphOverlay) {
        // Overlay mode: run the full pipeline, then overlay execution data.
        size_t deep_count = static_cast<size_t>(GraphMaxDeepDives < 0 ? 0 : GraphMaxDeepDives);
        auto result = lift_and_verify_named(ctx, binary_path, func_name, rva, deep_count);
        if (!result) {
            errs() << "  [FATAL] " << toString(result.takeError()) << "\n";
            return 2;
        }
        if (result->lift_failed) {
            errs() << "  [LIFTING] FAILED: " << result->lift_error << "\n";
            return 2;
        }
        if (!result->cfg) {
            errs() << "graph error: no CFG snapshot produced (internal error)\n";
            return 2;
        }

        // Build overlay data.
        lifted::visualization::OverlayData od;
        if (result->report)
            od.block_hits = &result->report->src_block_hits;

        // Find the requested divergence (GraphDivergenceIdx).
        const lifted::pipeline::RunOutcome *div_ptr = nullptr;
        if (result->report) {
            int want = GraphDivergenceIdx < 0 ? 0 : GraphDivergenceIdx;
            int seen = 0;
            for (const auto &stage : result->report->stages) {
                for (const auto &d : stage.divergences) {
                    if (seen == want) { div_ptr = &d; break; }
                    ++seen;
                }
                if (div_ptr) break;
            }
        }
        od.divergence = div_ptr;

        // Print pipeline summary to stderr.
        if (result->report)
            result->report->print(std::cerr);

        lifted::visualization::OverlayOptions oo;
        oo.cfg_opts = cfg_opts;
        dot = lifted::visualization::overlay_to_dot(*result->cfg, od, oo);
    } else {
        // CFG-only mode: lift without running the pipeline.
        auto arch = remill::Arch::Get(ctx, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
        auto binary = LIEF::Parser::parse(binary_path.string());
        if (!binary) {
            errs() << "graph error: failed to parse binary '" << binary_path.string() << "'\n";
            return 2;
        }
        lifted::BinaryContext bin_ctx(std::move(binary));
        auto cb_cfg = lifted::lifter::standard_lifter_config_t::from_standard_linux_binary(bin_ctx.binary());
        lifted::lifter::StandardLifterCallbacks callbacks(std::move(cb_cfg));
        auto lifter_or = lifted::lifter::Lifter::create(arch.get(), bin_ctx, &callbacks);
        if (!lifter_or) {
            errs() << "graph error: " << toString(lifter_or.takeError()) << "\n";
            return 2;
        }
        auto lift_result = (*lifter_or).lift(rva, {.instrument_bb_entry = false});
        if (!lift_result) {
            errs() << "graph error: " << toString(lift_result.takeError()) << "\n";
            return 2;
        }
        auto snapshot = lifted::visualization::make_cfg_snapshot(*lift_result, rva, func_name);
        dot = lifted::visualization::cfg_to_dot(snapshot, cfg_opts);
    }

    // -- Write or render output -----------------------------------------------
    std::string dot_path;
    bool        render = !GraphRender.empty();

    if (!GraphOutput.empty()) {
        dot_path = std::string(GraphOutput);
    } else if (render) {
        // Default DOT file name when rendering.
        dot_path = GraphOverlay ? "overlay.dot" : "cfg.dot";
    }

    if (!dot_path.empty()) {
        // Write DOT to file.
        std::error_code ec;
        raw_fd_ostream os(dot_path, ec);
        if (ec) {
            errs() << "graph error: cannot open '" << dot_path << "': " << ec.message() << "\n";
            return 2;
        }
        os << dot;
    } else {
        // Write DOT to stdout.
        outs() << dot;
    }

    // Render via graphviz if requested.
    if (render) {
        const std::string &fmt = GraphRender;
        // Derive rendered output path: same base as dot_path but with .fmt extension.
        std::string render_path;
        {
            fs::path dp(dot_path);
            render_path = dp.replace_extension("." + fmt).string();
        }
        std::string cmd = "dot -T" + fmt + " -o " + render_path + " " + dot_path;
        int rc = std::system(cmd.c_str());
        if (rc != 0) {
            errs() << "graph warning: graphviz 'dot' returned " << rc
                   << "; is graphviz installed?\n";
        } else {
            errs() << "Rendered: " << render_path << "\n";
        }
    }

    return 0;
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char **argv)
{
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

    cl::PrintHelpMessage();
    return 2;
}
