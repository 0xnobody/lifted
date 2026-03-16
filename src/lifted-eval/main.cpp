#include <cstdlib>
#include <filesystem>
#include <fstream>
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
#include "opt.hpp"
#include "suite.hpp"
#include "utils.hpp"

#include "bb_sync_info_builder.hpp"
#include "verification/jit_executor.hpp"
#include "verification/unicorn_executor.hpp"

#include "visualization/pipeline_overlay.hpp"

using namespace lifted;
using namespace lifted::eval;

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

    for (const auto &entry : suite)
    {
        if (entry.obfuscator == "")
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
            }
        }
    }

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

    // if (auto err = test_full_pipeline(context, "/home/atlas/lifted/build/src/evaluation/tum/libeval-anagram.so", 0x124A))
    //     llvm::errs() << "test_full_pipeline error: " << llvm::toString(std::move(err)) << "\n";

    if (auto err = lift_suite(context, EVAL_SUITE_SYNTHETIC_CSV))
        llvm::errs() << "synthetic suite error: " << llvm::toString(std::move(err)) << "\n";

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
