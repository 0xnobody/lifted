#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/raw_ostream.h>

#include <glog/logging.h>

#include "campaign_reporting.hpp"
#include "eval_pipeline.hpp"
#include "suite.hpp"
#include "utils.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <cstdio>
namespace fs = std::filesystem;
using namespace llvm;
using namespace lifted::eval;
using namespace lifted::fault_injection;

namespace
{
static cl::OptionCategory LiftedEvalCategory("lifted-eval options");

static cl::list<std::string> SuiteOpt(
    "suite",
    cl::desc("Suites to run (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));
static cl::opt<std::string> ObfuscatorOpt(
    "obfuscator",
    cl::desc("Obfuscator filter: none, polaris, or all (default: all)"),
    cl::init("all"),
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> TargetOpt(
    "target",
    cl::desc("Target stems to include (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> FuncOpt(
    "func",
    cl::desc("Function filters as target::func (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> IgnoreOpt(
    "ignore",
    cl::desc("Target stems or target::func labels to skip (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));

static cl::opt<bool> WithStandardOpt(
    "with-standard",
    cl::desc("Force standard evaluation campaigns on"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithoutStandardOpt(
    "without-standard",
    cl::desc("Disable standard evaluation campaigns"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithMutationOpt(
    "with-mutation",
    cl::desc("Force mutation campaigns on"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithoutMutationOpt(
    "without-mutation",
    cl::desc("Disable mutation campaigns"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithPolarisMutationOpt(
    "with-polaris-mutation",
    cl::desc("Enable mutation campaigns for Polaris targets"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));

static cl::opt<bool> Eg1Opt(
    "eg1",
    cl::desc("Run EG1 (raw lifted IR vs native binary)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> Eg2Opt(
    "eg2",
    cl::desc("Run EG2 (raw lifted IR vs O2 IR, gated by EG1)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> Eg3Opt(
    "eg3",
    cl::desc("Run EG3 (O2 self-test and mutation gating)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> AllEgsOpt(
    "all-egs",
    cl::desc("Run EG1 + EG2 + EG3 (default when no EG flag is supplied)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));

static cl::opt<int> MutationBudgetOpt(
    "mutation-budget",
    cl::desc("Mutation budget per function (default: 200)"),
    cl::init(200),
    cl::cat(LiftedEvalCategory));
static cl::opt<std::string> MutationSeedOpt(
    "mutation-seed",
    cl::desc("Mutation RNG seed in hex (default: 0x1337)"),
    cl::init("0x1337"),
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> MutationCategoriesOpt(
    "mutation-categories",
    cl::desc("Mutation category filter (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));

static cl::opt<std::string> OutputRootOpt(
    "output-root",
    cl::desc("Root directory for evaluation outputs"),
    cl::init("eval/results"),
    cl::cat(LiftedEvalCategory));
static cl::opt<int> MaxDeepDivesOpt(
    "max-deep-dives",
    cl::desc("Deep-dive divergences per function: 0=skip, 1=first (default)"),
    cl::init(1),
    cl::cat(LiftedEvalCategory));
static cl::opt<std::string> RenderCfgOpt(
    "render-cfg",
    cl::desc("Render CFGs via graphviz (svg|png|pdf)"),
    cl::init(""),
    cl::cat(LiftedEvalCategory));
static cl::opt<int> JobsOpt(
    "jobs",
    cl::desc("Functions to evaluate concurrently per campaign (0=hardware concurrency)"),
    cl::init(0),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> ListOpt(
    "list",
    cl::desc("Print the planned campaign matrix without executing it"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));

struct CampaignPlan
{
    std::string suite;
    std::string obfuscator; // raw: "" or "polaris"
    bool mutation = false;
    fs::path output_dir;
    EvaluationConfig config;
};

struct FunctionWorkItem
{
    size_t ordinal = 0;
    fs::path so_path;
    std::string binary;
    std::string func;
    uint64_t addr = 0;
};

std::string target_stem(const fs::path &so_path)
{
    std::string stem = so_path.stem().string();
    if (stem.starts_with("libeval-"))
        return stem.substr(8);
    if (stem.starts_with("lib"))
        return stem.substr(3);
    return stem;
}

std::string obfuscator_name(std::string_view obfuscator)
{
    return obfuscator.empty() ? "none" : std::string(obfuscator);
}

std::optional<MutationCategory> parse_category(const std::string &s)
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

std::string fmt_dbl(double value, int precision = 1)
{
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", precision, value);
    return buffer;
}

std::vector<std::string> default_suite_order()
{
    std::vector<std::string> ordered;
    const std::vector<std::string> thesis_order = {
        "synthetic",
        "tum-basic-algorithms",
        "tum-small-programs",
        "tum-simple-hash-functions",
        "gnu-coreutils",
    };
    const auto known_names = known_suite_names();
    const std::set<std::string> known(known_names.begin(), known_names.end());
    for (const auto &suite : thesis_order)
        if (known.count(suite))
            ordered.push_back(suite);
    return ordered;
}

bool phase_failed(const VerificationPhaseResult &phase)
{
    return phase.status == PhaseStatus::FAIL || phase.status == PhaseStatus::ERROR;
}

bool mutation_failed(const MutationPhaseResult &mutation)
{
    return mutation.status == MutationPhaseStatus::ERROR ||
           (mutation.status == MutationPhaseStatus::SKIPPED &&
            mutation.skip_reason != "disabled");
}

bool eg3_profile_failed(const Eg3ProfileResult &profile)
{
    return phase_failed(profile.selftest) || mutation_failed(profile.mutation);
}

void print_eg3_profile_summary(std::string_view label, const Eg3ProfileResult &profile)
{
    const char *profile_name = pipeline_checkpoint_profile_name(profile.profile);

    outs() << "  [EG3 " << label << " self-test/" << profile_name << "] "
           << phase_status_name(profile.selftest.status);
    if (!profile.selftest.skip_reason.empty())
        outs() << "  (" << profile.selftest.skip_reason << ")";
    else if (!profile.selftest.error.empty())
        outs() << "  (" << profile.selftest.error << ")";
    outs() << "\n";

    outs() << "  [EG3 " << label << " mutation/" << profile_name << "] "
           << mutation_phase_status_name(profile.mutation.status);
    if (profile.mutation.report)
    {
        outs() << "  (kill="
               << fmt_dbl(profile.mutation.report->mutation_score() * 100.0)
               << "% adj="
               << fmt_dbl(profile.mutation.report->adjusted_score() * 100.0)
               << "%)";
    }
    else if (!profile.mutation.skip_reason.empty())
    {
        outs() << "  (" << profile.mutation.skip_reason << ")";
    }
    else if (!profile.mutation.error.empty())
    {
        outs() << "  (" << profile.mutation.error << ")";
    }
    outs() << "\n";
}

int campaign_exit_code(const std::vector<EvaluatedFunction> &results)
{
    bool any_failure = false;
    for (const auto &entry : results)
    {
        if (entry.record.lift_failed || phase_failed(entry.record.raw_vs_native) ||
            phase_failed(entry.record.opt_vs_raw) ||
            eg3_profile_failed(entry.record.eg3_strict) ||
            eg3_profile_failed(entry.record.eg3_relaxed))
        {
            any_failure = true;
            continue;
        }
    }
    return any_failure ? 1 : 0;
}

void print_phase_summary(const EvaluatedFunction &entry)
{
    if (entry.record.lift_failed)
    {
        outs() << "  [LIFTING] FAIL  (" << entry.record.lift_error << ")\n";
        return;
    }

    outs() << "  [EG1] " << phase_status_name(entry.record.raw_vs_native.status);
    if (!entry.record.raw_vs_native.skip_reason.empty())
        outs() << "  (" << entry.record.raw_vs_native.skip_reason << ")";
    outs() << "\n";

    outs() << "  [EG2] " << phase_status_name(entry.record.opt_vs_raw.status);
    if (!entry.record.opt_vs_raw.skip_reason.empty())
        outs() << "  (" << entry.record.opt_vs_raw.skip_reason << ")";
    outs() << "\n";

    print_eg3_profile_summary("strict", entry.record.eg3_strict);
    print_eg3_profile_summary("relaxed", entry.record.eg3_relaxed);
}

std::string standard_dir_name(const std::string &suite, std::string_view obfuscator)
{
    return suite + "_" + obfuscator_name(obfuscator);
}

std::string mutation_dir_name(const std::string &suite,
                              std::string_view obfuscator,
                              size_t budget)
{
    if (obfuscator.empty() && budget == 200)
        return suite + "_200";
    return suite + "_mut_" + obfuscator_name(obfuscator) + "_b" + std::to_string(budget);
}

} // namespace

int main(int argc, char **argv)
{
    FLAGS_minloglevel = 1;
    google::InitGoogleLogging(argv[0]);

    InitLLVM X(argc, argv);
    cl::HideUnrelatedOptions(LiftedEvalCategory);
    cl::ParseCommandLineOptions(argc, argv, "lifted-eval — batch evaluation runner\n");

    if (WithStandardOpt && WithoutStandardOpt)
    {
        errs() << "lifted-eval error: cannot pass both --with-standard and --without-standard\n";
        return 2;
    }
    if (WithMutationOpt && WithoutMutationOpt)
    {
        errs() << "lifted-eval error: cannot pass both --with-mutation and --without-mutation\n";
        return 2;
    }

    const bool explicit_suite_filter = SuiteOpt.getNumOccurrences() > 0;
    std::vector<std::string> suites = explicit_suite_filter
        ? std::vector<std::string>(SuiteOpt.begin(), SuiteOpt.end())
        : default_suite_order();
    if (suites.empty())
    {
        errs() << "lifted-eval error: no suites available\n";
        return 2;
    }

    const auto known_names = known_suite_names();
    const std::set<std::string> known(known_names.begin(), known_names.end());
    for (const auto &suite : suites)
    {
        if (!known.count(suite))
        {
            errs() << "lifted-eval error: unknown suite '" << suite << "'\n";
            return 2;
        }
    }

    const bool run_standard = WithoutStandardOpt ? false : true;
    const bool run_mutation = WithoutMutationOpt ? false : true;
    const bool want_egs = AllEgsOpt || (!Eg1Opt && !Eg2Opt && !Eg3Opt);
    const bool want_eg1 = want_egs || Eg1Opt || Eg2Opt || Eg3Opt;
    const bool want_eg2 = want_egs || Eg2Opt || Eg3Opt;
    const bool want_eg3 = want_egs || Eg3Opt;

    if (!run_standard && !run_mutation)
    {
        errs() << "lifted-eval error: both standard and mutation campaigns are disabled\n";
        return 2;
    }

    MutationCampaignConfig mutation_cfg;
    mutation_cfg.budget = static_cast<size_t>(MutationBudgetOpt < 0 ? 200 : MutationBudgetOpt);
    try
    {
        mutation_cfg.seed = std::stoull(MutationSeedOpt, nullptr, 16);
    }
    catch (...)
    {
        errs() << "lifted-eval error: invalid mutation seed '" << MutationSeedOpt << "'\n";
        return 2;
    }
    for (const auto &cat_str : MutationCategoriesOpt)
    {
        auto cat = parse_category(cat_str);
        if (!cat)
        {
            errs() << "lifted-eval error: unknown mutation category '" << cat_str << "'\n";
            return 2;
        }
        mutation_cfg.filter_categories.push_back(*cat);
    }

    const std::set<std::string> target_filters(TargetOpt.begin(), TargetOpt.end());
    const std::set<std::string> func_filters(FuncOpt.begin(), FuncOpt.end());
    const std::set<std::string> ignore_filters(IgnoreOpt.begin(), IgnoreOpt.end());

    auto obfuscator_matches = [&](std::string_view obfuscator) -> bool
    {
        if (ObfuscatorOpt == "all")
            return true;
        if (ObfuscatorOpt == "none")
            return obfuscator.empty();
        return obfuscator == ObfuscatorOpt;
    };

    auto standard_config_for = [&](std::string_view obfuscator) {
        EvaluationConfig cfg;
        cfg.deep_dive_count = static_cast<size_t>(MaxDeepDivesOpt < 0 ? 0 : MaxDeepDivesOpt);
        cfg.obfuscator = std::string(obfuscator);
        cfg.run_raw_vs_native = want_eg1;
        cfg.run_opt_vs_raw = want_eg2;
        cfg.run_eg3_strict = want_eg3;
        cfg.run_eg3_relaxed = want_eg3;
        cfg.run_mutation = false;
        return cfg;
    };

    auto mutation_config_for = [&](std::string_view obfuscator) {
        EvaluationConfig cfg;
        cfg.deep_dive_count = static_cast<size_t>(MaxDeepDivesOpt < 0 ? 0 : MaxDeepDivesOpt);
        cfg.obfuscator = std::string(obfuscator);
        cfg.run_raw_vs_native = true;
        cfg.run_opt_vs_raw = true;
        cfg.run_eg3_strict = true;
        cfg.run_eg3_relaxed = true;
        cfg.run_mutation = true;
        cfg.mutation_config = mutation_cfg;
        return cfg;
    };

    std::vector<CampaignPlan> plans;
    for (const auto &suite : suites)
    {
        const bool default_suite_matrix = !explicit_suite_filter && ObfuscatorOpt == "all";
        std::vector<std::string> standard_obfuscators;
        if (default_suite_matrix && suite == "gnu-coreutils")
            standard_obfuscators = {""};
        else
            standard_obfuscators = {"", "polaris"};

        if (run_standard)
        {
            for (const auto &obfuscator : standard_obfuscators)
            {
                if (!obfuscator_matches(obfuscator))
                    continue;
                plans.push_back(CampaignPlan{
                    .suite = suite,
                    .obfuscator = obfuscator,
                    .mutation = false,
                    .output_dir = fs::path(std::string(OutputRootOpt)) / standard_dir_name(suite, obfuscator),
                    .config = standard_config_for(obfuscator),
                });
            }
        }

        if (run_mutation)
        {
            std::vector<std::string> mutation_obfuscators = {""};
            if (WithPolarisMutationOpt || ObfuscatorOpt == "polaris")
                mutation_obfuscators.push_back("polaris");
            for (const auto &obfuscator : mutation_obfuscators)
            {
                if (!obfuscator_matches(obfuscator))
                    continue;
                plans.push_back(CampaignPlan{
                    .suite = suite,
                    .obfuscator = obfuscator,
                    .mutation = true,
                    .output_dir = fs::path(std::string(OutputRootOpt)) / mutation_dir_name(suite, obfuscator, mutation_cfg.budget),
                    .config = mutation_config_for(obfuscator),
                });
            }
        }
    }

    if (plans.empty())
    {
        errs() << "lifted-eval error: no campaigns selected\n";
        return 2;
    }

    if (ListOpt)
    {
        outs() << "Planned campaigns:\n";
        for (const auto &plan : plans)
        {
            outs() << "  - suite=" << plan.suite
                   << " obfuscator=" << obfuscator_name(plan.obfuscator)
                   << " mode=" << (plan.mutation ? "mutation" : "standard")
                   << " out=" << plan.output_dir.string() << "\n";
        }
        return 0;
    }
    const auto auto_job_count = []() -> size_t {
        const unsigned hint = std::thread::hardware_concurrency();
        return hint == 0 ? 1 : static_cast<size_t>(hint);
    };
    const auto configured_job_count = [&]() -> size_t {
        return JobsOpt <= 0 ? auto_job_count() : static_cast<size_t>(JobsOpt);
    };

    int overall_exit = 0;
    bool any_results = false;

    for (const auto &plan : plans)
    {
        auto suite_csv = resolve_suite_name(plan.suite);
        if (!suite_csv)
        {
            errs() << "lifted-eval error: cannot resolve suite '" << plan.suite << "'\n";
            return 2;
        }

        auto entries = parse_suite_csv(*suite_csv);
        if (entries.empty())
        {
            errs() << "lifted-eval error: no entries in suite '" << plan.suite << "'\n";
            return 2;
        }

        std::error_code ec;
        fs::create_directories(plan.output_dir, ec);
        if (ec)
        {
            errs() << "lifted-eval error: cannot create output dir '"
                   << plan.output_dir.string() << "': " << ec.message() << "\n";
            return 2;
        }

        outs() << "\n=== Campaign: " << plan.suite
               << " / " << obfuscator_name(plan.obfuscator)
               << " / " << (plan.mutation ? "mutation" : "standard")
               << " ===\n";

        std::vector<FunctionWorkItem> work_items;
        for (const auto &entry : entries)
        {
            if (entry.obfuscator != plan.obfuscator)
                continue;
            const std::string stem = target_stem(entry.so_path);
            if (!target_filters.empty() && !target_filters.count(stem))
                continue;
            if (ignore_filters.count(stem))
                continue;

            auto targets = parse_targets_csv(entry.targets_csv_path);
            for (const auto &target : targets)
            {
                const std::string label = stem + "::" + target.func_name;
                if (!func_filters.empty() && !func_filters.count(label))
                    continue;
                if (ignore_filters.count(label))
                    continue;

                work_items.push_back(FunctionWorkItem{
                    .ordinal = work_items.size() + 1,
                    .so_path = entry.so_path,
                    .binary = stem,
                    .func = target.func_name,
                    .addr = target.addr,
                });
            }
        }

        if (work_items.empty())
        {
            outs() << "  [SKIPPED] no matching functions for this campaign\n";
            continue;
        }

        any_results = true;
        const size_t jobs = std::max<size_t>(1, std::min(work_items.size(), configured_job_count()));
        outs() << "  [INFO] jobs=" << jobs << "\n";

        std::vector<std::optional<EvaluatedFunction>> ordered_results(work_items.size());
        std::vector<std::string> fatal_errors(work_items.size());
        std::atomic_size_t next_index{0};
        std::vector<std::thread> workers;
        workers.reserve(jobs);

        for (size_t worker = 0; worker < jobs; ++worker)
        {
            workers.emplace_back([&] {
                llvm::LLVMContext local_ctx;
                while (true)
                {
                    const size_t index = next_index.fetch_add(1);
                    if (index >= work_items.size())
                        break;

                    const auto &item = work_items[index];
                    auto record_or = run_evaluation_named(
                        local_ctx, item.so_path, item.func, item.addr, plan.config);
                    if (!record_or)
                    {
                        fatal_errors[index] = toString(record_or.takeError());
                        continue;
                    }

                    ordered_results[index] = EvaluatedFunction{
                        .suite = plan.suite,
                        .binary = item.binary,
                        .func = item.func,
                        .obfuscator = obfuscator_name(plan.obfuscator),
                        .record = std::move(*record_or),
                    };
                }
            });
        }

        for (auto &worker : workers)
            worker.join();

        for (size_t index = 0; index < fatal_errors.size(); ++index)
        {
            if (!fatal_errors[index].empty())
            {
                errs() << "  [FATAL] " << fatal_errors[index] << "\n";
                return 2;
            }
            if (!ordered_results[index].has_value())
            {
                errs() << "  [FATAL] missing evaluation result for "
                       << work_items[index].binary << "::" << work_items[index].func << "\n";
                return 2;
            }
        }

        std::vector<EvaluatedFunction> results;
        results.reserve(ordered_results.size());
        for (size_t index = 0; index < ordered_results.size(); ++index)
        {
            const auto &item = work_items[index];
            outs() << "\n--- [" << item.ordinal << "/" << work_items.size() << "] "
                   << item.so_path.filename().string() << " :: " << item.func
                   << " @ " << llvm::format_hex(item.addr, 18) << " ---\n";

            results.push_back(std::move(*ordered_results[index]));
            print_phase_summary(results.back());
            write_function_reports(results.back(), plan.output_dir);
            write_function_dot(results.back(), plan.output_dir, RenderCfgOpt);
        }

        const std::string label = plan.suite + " (obfuscator=" + obfuscator_name(plan.obfuscator)
            + ", mode=" + (plan.mutation ? std::string("mutation") : std::string("standard")) + ")";
        write_campaign_artifacts(label, results, plan.output_dir);
        overall_exit = std::max(overall_exit, campaign_exit_code(results));
    }

    if (!any_results)
    {
        errs() << "lifted-eval error: filters excluded every function in every selected campaign\n";
        return 2;
    }

    return overall_exit;
}
