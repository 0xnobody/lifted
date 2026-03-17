#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <glog/logging.h>

#include "abi/all_registers_cc.hpp"
#include "abi/state_fold.hpp"
#include "abi/systemv_x64.hpp"

#include "eval_pipeline.hpp"
#include "lifter/lifter.hpp"
#include "lifter/polaris_lifter_callbacks.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include "mutation_campaign.hpp"
#include "opt.hpp"
#include "suite.hpp"
#include "utils.hpp"

#include "bb_sync_info_builder.hpp"
#include "verification/jit_executor.hpp"
#include "verification/unicorn_executor.hpp"

#include "visualization/pipeline_overlay.hpp"

using namespace lifted;
using namespace lifted::eval;
using namespace lifted::fault_injection;

// ── Bulk mutation suite runner ───────────────────────────────────────────────
//
// Reads a suite CSV and runs MutationCampaign::run() on every listed function.
// Prints a per-function report to stdout and writes a summary CSV to csv_out.
static llvm::Error mutate_suite(llvm::LLVMContext &context,
                                const std::filesystem::path &suite_csv_path,
                                const MutationCampaign::Config cfg,
                                const std::filesystem::path &csv_out)
{
    llvm::outs() << "\n=== Mutation suite: " << suite_csv_path.filename().string() << " ===\n";

    auto suite = parse_suite_csv(suite_csv_path);
    if (suite.empty())
    {
        llvm::errs() << "mutate_suite: no entries in " << suite_csv_path.string() << "\n";
        return llvm::Error::success();
    }

    // Open CSV output file.
    std::ofstream csv(csv_out);
    if (!csv.is_open())
        llvm::errs() << "mutate_suite: cannot open " << csv_out.string() << " for writing\n";
    else
        csv << "binary,func,total_enumerated,total_mutants,killed,survived,equivalent,errors,"
               "mutation_score_pct,adjusted_score_pct\n";

    for (const auto &entry : suite)
    {
        auto targets = parse_targets_csv(entry.targets_csv_path);
        if (targets.empty())
        {
            llvm::errs() << "  no targets in " << entry.targets_csv_path.string() << "\n";
            continue;
        }

        std::string bin_stem = entry.so_path.stem().string();
        if (bin_stem.starts_with("libeval-"))
            bin_stem = bin_stem.substr(8);

        for (const auto &target : targets)
        {
            llvm::outs() << "  [MUTATE] " << bin_stem << "::" << target.func_name
                         << " @ " << llvm::format_hex(target.addr, 18) << "\n";

            auto report_or = lift_and_mutate_named(
                context, entry.so_path, target.func_name, target.addr, cfg);
            if (!report_or)
            {
                llvm::errs() << "    [FATAL] " << llvm::toString(report_or.takeError()) << "\n";
                continue;
            }

            if (report_or->lift_failed)
            {
                llvm::errs() << "    [ERROR] " << report_or->lift_error << "\n";
                continue;
            }

            const auto &rpt = *report_or->report;
            rpt.print(std::cout);

            // Append to CSV.
            if (csv.is_open())
            {
                csv << bin_stem << "," << target.func_name << ","
                    << rpt.total_enumerated << "," << rpt.total_mutants << ","
                    << rpt.killed << "," << rpt.survived << ","
                    << rpt.equivalent << "," << rpt.errors << ","
                    << std::fixed << std::setprecision(1)
                    << (100.0 * rpt.mutation_score()) << ","
                    << (100.0 * rpt.adjusted_score()) << "\n";
            }
        }
    }

    return llvm::Error::success();
}
// ── Suite runner
// ─────────────────────────────────────────────────────────────── Reads a suite
// CSV (so_path,targets_csv_path,obfuscator) and lifts every listed function.
static llvm::Error lift_suite(llvm::LLVMContext &context,
                              const std::filesystem::path &suite_csv_path)
{
    llvm::outs() << "\n=== Suite: " << suite_csv_path.filename().string()
                 << " ===\n";

    auto suite = parse_suite_csv(suite_csv_path);
    if (suite.empty())
    {
        llvm::errs() << "lift_suite: no entries in " << suite_csv_path.string()
                     << "\n";
        return llvm::Error::success();
    }

    int num_diverged = 0;
    int num_total = 0;
    for (const auto &entry : suite)
    {
        if (entry.obfuscator == "polaris")
            continue;

        auto targets = parse_targets_csv(entry.targets_csv_path);
        if (targets.empty())
        {
            llvm::errs() << "  no targets in " << entry.targets_csv_path.string()
                         << "\n";
            continue;
        }

        for (const auto &target : targets)
        {
            std::string eval_name =
                entry.so_path.filename().string() + "." + target.func_name;

            std::ofstream report_file("/tmp/eval_" + eval_name + "_report.txt");

            llvm::outs() << "  Lifting " << entry.so_path.filename().string()
                         << "::" << target.func_name << " @ "
                         << llvm::format_hex(target.addr, 18) << "\n";

            auto result = lift_and_verify_named(context, entry.so_path,
                                                target.func_name, target.addr,
                                                1, entry.obfuscator);
            if (!result)
            {
                llvm::errs() << "  FAILED: " << llvm::toString(result.takeError())
                             << "\n";
                continue;
            }

            if (result->lift_failed)
            {
                llvm::errs() << "  Lifting failed: " << result->lift_error << "\n";
                continue;
            }

            if (result->lift_stats)
                result->lift_stats->print(report_file);

            if (result->report)
                result->report->print(report_file);

            if (result->deep_dive)
                result->deep_dive->print(report_file);

            visualization::OverlayData od = {.block_hits =
                                                 &result->report->src_block_hits};

            const lifted::pipeline::RunOutcome *div_ptr = nullptr;
            if (result->report)
            {
                for (const auto &stage : result->report->stages)
                {
                    for (const auto &d : stage.divergences)
                    {
                        div_ptr = &d;
                        break;
                    }
                    if (div_ptr)
                        break;
                }
            }
            od.divergence = div_ptr;

            auto dot_output = visualization::overlay_to_dot(*result->cfg, od);

            std::ofstream dot_file("/tmp/eval_" + eval_name + "_cfg.dot");
            dot_file << dot_output;
            dot_file.close();

            system(("dot -Tsvg /tmp/eval_" + eval_name + "_cfg.dot -o /tmp/eval_" +
                    eval_name + "_cfg.svg")
                       .c_str());

            if (div_ptr)
            {
                llvm::outs() << "[DIVERGED]\n";
                num_diverged++;
            }
            num_total++;
        }
    }

    llvm::outs() << "Total: " << num_total << ", Diverged: " << num_diverged << "\n";

    return llvm::Error::success();
}

llvm::Error test_full_pipeline(llvm::LLVMContext &context,
                               const std::filesystem::path &path,
                               uint64_t entry_rva)
{
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchAMD64);

    auto binary = LIEF::Parser::parse(path);
    if (!binary)
        return llvm::make_error<llvm::StringError>("Failed to parse binary: " +
                                                       path.string(),
                                                   llvm::inconvertibleErrorCode());

    lifted::BinaryContext bin_ctx(std::move(binary));

    lifter::standard_lifter_config_t cb_config =
        lifter::standard_lifter_config_t::from_standard_linux_binary(
            bin_ctx.binary());

    lifter::StandardLifterCallbacks callbacks(std::move(cb_config));
    auto the_lifter_or = lifter::Lifter::create(arch.get(), bin_ctx, &callbacks);
    if (!the_lifter_or)
        return the_lifter_or.takeError();
    auto &the_lifter = *the_lifter_or;

    auto entry_ann = std::make_unique<lifted::fnc_annotation_t>();
    entry_ann->cc = &lifted::abi::AllRegistersCC::get();
    annotation_id_t entry_annotation_id = bin_ctx.add_annotation(std::move(entry_ann));

    auto lift_result = the_lifter.lift(entry_rva, entry_annotation_id, {.instrument_bb_entry = true});
    if (!lift_result)
    {
        return lift_result.takeError();
    }

    lift_result->stats.print(std::cout);

    auto bb_sync_info = eval::make_bb_sync_info(lift_result->basic_blocks);

    std::string fn_name = lift_result->lifted_function->getName().str();

    // Create executors eagerly — no factory indirection.
    // Clone module so original is still available for optimization later.
    auto jit_or = verification::JITExecutor::create(
        llvm::CloneModule(*lift_result->module), fn_name);
    if (!jit_or)
        return jit_or.takeError();
    auto jit = std::shared_ptr<verification::Executor>(std::move(*jit_or));

    auto uc_or = verification::UnicornExecutor::create(bin_ctx, {}, entry_rva,
                                                       verification::UnicornExecutor::Flags::NONE,
                                                       bb_sync_info);
    if (!uc_or)
        return uc_or.takeError();
    auto uc = std::shared_ptr<verification::Executor>(std::move(*uc_or));

    // Pipeline 1: raw JIT vs Unicorn.
    pipeline::Pipeline p1(eval::make_default_pipeline(
        "raw_lifted", jit, uc, eval::PipelineCheckpointProfile::RAW_STRICT));

    auto r1 = p1.run(bin_ctx, entry_rva);
    if (!r1)
        return r1.takeError();

    r1->print(std::cout);
    utils::output_to_file("/home/atlas/lifted/out/raw_lifted.ll", lift_result->module.get());

    // Run some 'deobfuscations'
    auto clone = llvm::CloneModule(*lift_result->module);

    opt::always_inline(clone.get());

    auto unfolded_or = lifted::abi::unfold_function_state_recursive(clone->getFunction(fn_name), bin_ctx);
    if (!unfolded_or)
        return unfolded_or.takeError();
    (*unfolded_or)->setLinkage(llvm::GlobalValue::ExternalLinkage);

    utils::output_to_file("/home/atlas/lifted/out/unfolded.ll", clone.get());

    opt::always_inline(clone.get());
    opt::default_opt(clone.get());

    utils::output_to_file("/home/atlas/lifted/out/unfolded_deob.ll", clone.get());

    auto refolded_or = lifted::abi::fold_function_state_recursive(*unfolded_or, bin_ctx);
    if (!refolded_or)
        return refolded_or.takeError();
    (*refolded_or)->setLinkage(llvm::GlobalValue::ExternalLinkage);

    opt::always_inline(clone.get());

    utils::output_to_file("/home/atlas/lifted/out/refolded_deob.ll", clone.get());

    // Create new JIT from optimized module.
    auto opt_jit_or = verification::JITExecutor::create(
        std::move(clone), (*refolded_or)->getName().str());
    if (!opt_jit_or)
        return opt_jit_or.takeError();
    auto opt_jit =
        std::shared_ptr<verification::Executor>(std::move(*opt_jit_or));

    // Pipeline 2: reuse raw JIT as baseline, compare against optimized JIT with
    // relaxed synchronization and dimension policy.
    pipeline::Pipeline p2(
        eval::make_default_pipeline(
            "opt_vs_raw_lifted", jit, opt_jit,
            eval::PipelineCheckpointProfile::OPTIMIZED_RELAXED));

    auto r2 = p2.run(bin_ctx, entry_rva);
    if (!r2)
        return r2.takeError();

    r2->print(std::cout);
    utils::output_to_file("/home/atlas/lifted/out/raw_lifted_opt1.ll",
                          lift_result->module.get());

    return llvm::Error::success();
}

int main(int argc, char **argv)
{
    FLAGS_minloglevel = 1;
    google::InitGoogleLogging(argv[0]);

    llvm::LLVMContext context;

    // Simple argument parsing for mutation mode:
    //   lifted-eval --mode mutate --suite <name> [--budget N] [--seed 0xHEX] [--output path.csv]
    // All other invocations fall through to the legacy lift_suite behaviour.
    bool mode_mutate = false;
    std::string mutate_suite_name;
    std::string mutate_output = "/tmp/mutation_results.csv";
    MutationCampaign::Config mutate_cfg;

    for (int i = 1; i < argc; ++i)
    {
        std::string_view arg = argv[i];
        if (arg == "--mode" && i + 1 < argc)
        {
            ++i;
            mode_mutate = (std::string_view(argv[i]) == "mutate");
        }
        else if (arg == "--suite" && i + 1 < argc)
        {
            ++i;
            mutate_suite_name = argv[i];
        }
        else if (arg == "--budget" && i + 1 < argc)
        {
            ++i;
            mutate_cfg.budget = static_cast<size_t>(std::atoll(argv[i]));
        }
        else if (arg == "--seed" && i + 1 < argc)
        {
            ++i;
            mutate_cfg.seed = static_cast<uint64_t>(std::stoull(argv[i], nullptr, 16));
        }
        else if (arg == "--output" && i + 1 < argc)
        {
            ++i;
            mutate_output = argv[i];
        }
    }

    if (mode_mutate)
    {
        // Resolve suite name to CSV path.
        std::filesystem::path csv_path;
        if (!mutate_suite_name.empty())
        {
            auto p = eval::resolve_suite_name(mutate_suite_name);
            if (!p)
            {
                llvm::errs() << "lifted-eval mutate: unknown suite '" << mutate_suite_name
                             << "'. Use --suite <name> with a known suite.\n";
                return EXIT_FAILURE;
            }
            csv_path = *p;
        }
        else
        {
            // Default to synthetic suite if available.
#ifdef EVAL_SUITE_SYNTHETIC_CSV
            csv_path = EVAL_SUITE_SYNTHETIC_CSV;
#else
            llvm::errs() << "lifted-eval mutate: no --suite argument and no default suite baked in.\n";
            return EXIT_FAILURE;
#endif
        }

        if (auto err = mutate_suite(context, csv_path, mutate_cfg, mutate_output))
        {
            llvm::errs() << "mutate_suite error: " << llvm::toString(std::move(err)) << "\n";
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Legacy mode: run the hardcoded lift_suite calls.
    // if (auto err = test_full_pipeline(context, "/home/atlas/lifted/build/src/evaluation/tum/libeval-anagram.so", 0x124A))
    //     llvm::errs() << "test_full_pipeline error: " << llvm::toString(std::move(err)) << "\n";

    // if (auto err = lift_suite(context, EVAL_SUITE_SYNTHETIC_CSV))
    //     llvm::errs() << "synthetic suite error: " << llvm::toString(std::move(err)) << "\n";

    if (auto err = lift_suite(context, EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV))
        llvm::errs() << "tum-simple-hash-functions suite error: " << llvm::toString(std::move(err)) << "\n";

    if (auto err = lift_suite(context, EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV))
        llvm::errs() << "tum-small-programs suite error: " << llvm::toString(std::move(err)) << "\n";

    if (auto err = lift_suite(context, EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV))
        llvm::errs() << "tum-basic-algorithms suite error: "
                     << llvm::toString(std::move(err)) << "\n";

    if (auto err = lift_suite(context, EVAL_SUITE_GNU_COREUTILS_CSV))
        llvm::errs() << "gnu-coreutils suite error: " << llvm::toString(std::move(err)) << "\n";

    return EXIT_SUCCESS;
}
