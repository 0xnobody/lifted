#include <cstdlib>
#include <filesystem>
#include <iostream>

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <glog/logging.h>

#include "suite.hpp"
#include "eval_pipeline.hpp"
#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include "opt.hpp"

#include "verification/jit_executor.hpp"
#include "verification/unicorn_executor.hpp"

using namespace lifted;
using namespace lifted::eval;

// ── Suite runner ───────────────────────────────────────────────────────────────
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

            auto result = lift_and_verify_named(context, entry.so_path,
                                                target.func_name, target.addr);
            if (!result)
            {
                llvm::errs() << "  FAILED: " << llvm::toString(result.takeError()) << "\n";
                continue;
            }

            if (result->lift_failed)
            {
                llvm::errs() << "  Lifting failed: " << result->lift_error << "\n";
                continue;
            }

            if (result->report)
                result->report->print(std::cout);

            if (result->deep_dive)
                result->deep_dive->print(std::cout);
        }
    }

    return llvm::Error::success();
}

llvm::Error test_full_pipeline(llvm::LLVMContext &context,
                               const std::filesystem::path &path,
                               uint64_t entry_rva)
{
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);

    std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(path);
    if (!binary)
        return llvm::make_error<llvm::StringError>(
            "Failed to parse binary: " + path.string(),
            llvm::inconvertibleErrorCode());

    lifter::standard_lifter_config_t cb_config = lifter::standard_lifter_config_t::from_standard_linux_binary(*binary);

    lifter::StandardLifterCallbacks callbacks(std::move(cb_config));
    auto the_lifter_or = lifter::Lifter::create(arch.get(), binary.get(), &callbacks);
    if (!the_lifter_or)
        return the_lifter_or.takeError();
    auto &the_lifter = *the_lifter_or;

    auto lift_result = the_lifter.lift(entry_rva, {.instrument_bb_entry = true});
    if (!lift_result)
    {
        return lift_result.takeError();
    }

    // Collect fallthrough edges before the module is moved into the JIT factory.
    std::set<std::pair<uint64_t, uint64_t>> fallthrough_edges;
    for (const auto &edge : lift_result->edges)
        if (edge.type == lifter::edge_t::Type::FALLTHROUGH)
            fallthrough_edges.insert({edge.source, edge.dest});

    std::string fn_name = lift_result->lifted_function->getName().str();

    // std::function requires a copyable callable, so wrap the unique_ptr in a
    // shared_ptr.  The factory is invoked exactly once by the pipeline.
    auto mod_holder =
        std::make_shared<std::unique_ptr<llvm::Module>>(llvm::CloneModule(*lift_result->module));

    auto make_jit = [mod_holder, fn_name, fallthrough_edges]()
        -> llvm::Expected<std::unique_ptr<verification::Executor>>
    {
        return verification::JITExecutor::create(
            std::move(*mod_holder), fn_name, fallthrough_edges);
    };

    auto make_unicorn = [binary, entry_rva]()
        -> llvm::Expected<std::unique_ptr<verification::Executor>>
    {
        return verification::UnicornExecutor::create(binary, {}, entry_rva);
    };

    pipeline::Pipeline p1(eval::make_default_pipeline("raw_lifted", std::move(make_jit), std::move(make_unicorn)));

    auto r1 = p1.run(binary, entry_rva);
    if (!r1)
        return r1.takeError();

    r1->print(std::cout);

    // Run some 'deobfuscations'
    opt::always_inline(lift_result->module.get());
    opt::default_opt(lift_result->module.get());

    auto opt_mod_holder =
        std::make_shared<std::unique_ptr<llvm::Module>>(llvm::CloneModule(*lift_result->module));

    auto make_opt_jit = [opt_mod_holder, fn_name, fallthrough_edges]()
        -> llvm::Expected<std::unique_ptr<verification::Executor>>
    {
        return verification::JITExecutor::create(
            std::move(*opt_mod_holder), fn_name, fallthrough_edges);
    };

    pipeline::Pipeline p2(eval::make_default_pipeline("opt_vs_raw_lifted", std::move(make_jit), std::move(make_opt_jit)));

    auto r2 = p2.run(binary, entry_rva);
    if (!r2)
        return r2.takeError();

    return llvm::Error::success();
}

int main(int /*argc*/, char ** /*argv*/)
{
    llvm::LLVMContext context;

    test_full_pipeline(context, "/home/atlas/lifted/build/src/evaluation/tum/libeval-anagram.so", 0x124A);

    // if (auto err = lift_suite(context, EVAL_SUITE_SYNTHETIC_CSV))
    //     llvm::errs() << "synthetic suite error: " << llvm::toString(std::move(err)) << "\n";

    // if (auto err = lift_suite(context, EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV))
    //     llvm::errs() << "tum-basic-algorithms suite error: " << llvm::toString(std::move(err)) << "\n";

    // if (auto err = lift_suite(context, EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV))
    //     llvm::errs() << "tum-small-programs suite error: " << llvm::toString(std::move(err)) << "\n";
    //
    // if (auto err = lift_suite(context, EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV))
    //    llvm::errs() << "tum-simple-hash-functions suite error: " << llvm::toString(std::move(err)) << "\n";

    return EXIT_SUCCESS;
}
