#include <cstdlib>
#include <memory>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <filesystem>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include "helpers.hpp"
#include "utils.hpp"
#include "opt.hpp"

#include "lifter2.hpp"

#include "abi/systemv_x64.hpp"

#include "verification/jit_executor.hpp"
#include "verification/unicorn_executor.hpp"

#include "pipeline/pipeline.hpp"
#include "pipeline/stages/seed_sweep_stage.hpp"

#include "suite.hpp"
#include "utils.hpp"

using namespace lifted;
using namespace lifted::eval;

// Core lifting + verification path.  Takes an explicit entry RVA so the
// caller can supply addresses obtained from the CSV (no export lookup needed).
llvm::Error lift_and_verify_named(llvm::LLVMContext &context,
                                  const std::filesystem::path &path,
                                  const std::string &func_name,
                                  uint64_t entry_rva)
{
    // TODO: figure out how to avoid loading arch/semantics for each lift
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
    auto lift_module = remill::LoadArchSemantics(arch.get());

    std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(path);
    if (!binary)
    {
        return llvm::make_error<llvm::StringError>("Failed to parse binary: " + path.string(),
                                                   llvm::inconvertibleErrorCode());
    }

    lifted::abi::SystemVx64CC CC;

    std::set<llvm::AddressRange> const_rva_ranges;
    // const_rva_ranges.insert(llvm::AddressRange{0x4030, 0x4080}); // obfuscator dependent

    std::set<llvm::AddressRange> got_table_rva_ranges;
    if (auto got_range = get_section_bounds(*binary, ".got"))
        got_table_rva_ranges.insert(*got_range);

    std::set<llvm::AddressRange> ext_func_rva_ranges;
    if (auto plt_range = get_section_bounds(*binary, ".plt.sec"))
        ext_func_rva_ranges.insert(*plt_range);

    Lifter lifter(arch.get(),
                  binary.get(),
                  lift_module.get(),
                  const_rva_ranges,
                  got_table_rva_ranges,
                  ext_func_rva_ranges,
                  nullptr,
                  &CC);

    auto lift_result = lifter.Lift(entry_rva, true);
    if (!lift_result)
    {
        llvm::errs() << "  Lifting failed: "
                     << llvm::toString(lift_result.takeError()) << "\n";
        return llvm::Error::success();
    }

    utils::output_to_file("/home/atlas/lifted/out/lifted.ll", lift_result->Module.get());

    // Collect fallthrough edges before the module is moved into the JIT factory.
    std::set<std::pair<uint64_t, uint64_t>> fallthrough_edges;
    for (const auto &edge : lift_result->Edges)
        if (edge.Type == Edge::Type::FALLTHROUGH)
            fallthrough_edges.insert({edge.Source, edge.Dest});

    std::string fn_name = lift_result->LiftedFunction->getName().str();

    // ── JIT executor factory (callable exactly once — moves the module) ───────
    // std::function requires a copyable callable, so we wrap the unique_ptr in a
    // shared_ptr.  The factory is called exactly once by the pipeline.
    auto mod_holder =
        std::make_shared<std::unique_ptr<llvm::Module>>(std::move(lift_result->Module));
    auto make_jit = [mod_holder, fn_name, fallthrough_edges]()
        -> llvm::Expected<std::unique_ptr<verification::Executor>>
    {
        return verification::JITExecutor::create(
            std::move(*mod_holder), fn_name, fallthrough_edges);
    };

    // ── Unicorn executor factory (ext_calls start empty) ─────────────────────
    // The pipeline discovers external call targets at runtime and forwards
    // them to the executor via hint_external_rvas before each tgt run.
    auto make_unicorn = [binary, entry_rva]()
        -> llvm::Expected<std::unique_ptr<verification::Executor>>
    {
        return verification::UnicornExecutor::create(binary, {}, entry_rva);
    };

    // ── Pipeline configuration ────────────────────────────────────────────────
    pipeline::RunConfig base_cfg{
        .seed = 0x1337,
        .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
            {.size_bytes = 0, .value = 0, .inv_prob = 10},
            {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFF, .inv_prob = 10},
        }),
        .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
            verification::value_constraints_t{.max = 0x20'000, .alignment = 8}),
        .bb_limit = 50'000,
        .loop_limit = 20,
    };

    pipeline::PipelineSpec spec;
    spec.name = "raw_vs_native[" + func_name + "]";
    spec.executors = {std::move(make_jit), std::move(make_unicorn)};
    spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(base_cfg, 50));

    pipeline::Pipeline pl(std::move(spec));
    auto report = pl.run(binary, entry_rva);

    if (!report)
    {
        llvm::errs() << "  Pipeline failed: "
                     << llvm::toString(report.takeError()) << "\n";
        return llvm::Error::success();
    }

    report->print(std::cout);
    return llvm::Error::success();
}

// Thin wrapper for callers that want to look up an export by name at runtime.
llvm::Error lift_and_verify(llvm::LLVMContext &context,
                            std::filesystem::path path,
                            const llvm::Module * /*defs_module*/)
{
    std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(path);
    if (!binary)
        return llvm::make_error<llvm::StringError>("Failed to parse binary: " + path.string(),
                                                   llvm::inconvertibleErrorCode());
    auto rva = rva_from_export(*binary, "test");
    if (!rva)
        return rva.takeError();
    return lift_and_verify_named(context, path, "test", *rva);
}

// ── Suite runner ──────────────────────────────────────────────────────────────
// Reads a suite CSV (so_path,targets_csv_path) and lifts every listed function.
static llvm::Error lift_suite(llvm::LLVMContext &context,
                              const std::filesystem::path &suite_csv_path)
{
    llvm::outs() << "\n=== Suite: " << suite_csv_path.filename().string() << " ===\n";

    auto suite = parse_suite_csv(suite_csv_path);
    if (suite.empty())
    {
        llvm::errs() << "lift_suite: no entries in " << suite_csv_path.string() << "\n";
        return llvm::Error::success();
    }

    for (const auto &entry : suite)
    {
        auto targets = parse_targets_csv(entry.targets_csv_path);
        if (targets.empty())
        {
            llvm::errs() << "  no targets in " << entry.targets_csv_path.string() << "\n";
            continue;
        }

        for (const auto &target : targets)
        {
            llvm::outs() << "  Lifting " << entry.so_path.filename().string()
                         << "::" << target.func_name
                         << " @ " << llvm::format_hex(target.addr, 18) << "\n";

            if (auto err = lift_and_verify_named(context, entry.so_path,
                                                 target.func_name, target.addr))
            {
                llvm::errs() << "  FAILED: " << llvm::toString(std::move(err)) << "\n";
            }
        }
    }

    return llvm::Error::success();
}

int main(int argc, char **argv)
{
    llvm::LLVMContext context;

    // lift_and_verify_named(context, "/home/atlas/lifted/build/src/evaluation/tum/libeval-binarymult.so", "binarymult", 0x127A);
    // return EXIT_SUCCESS;

    // if (auto err = lift_suite(context, EVAL_SUITE_SYNTHETIC_CSV))
    //     llvm::errs() << "synthetic suite error: " << llvm::toString(std::move(err)) << "\n";

    if (auto err = lift_suite(context, EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV))
        llvm::errs() << "tum-basic-algorithms suite error: " << llvm::toString(std::move(err)) << "\n";

    // if (auto err = lift_suite(context, EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV))
    //     llvm::errs() << "tum-small-programs suite error: " << llvm::toString(std::move(err)) << "\n";
    //
    // if (auto err = lift_suite(context, EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV))
    //    llvm::errs() << "tum-simple-hash-functions suite error: " << llvm::toString(std::move(err)) << "\n";

    return EXIT_SUCCESS;
}
