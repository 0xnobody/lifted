#include <cstdlib>
#include <filesystem>
#include <iostream>

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include "suite.hpp"
#include "eval_pipeline.hpp"

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

int main(int /*argc*/, char ** /*argv*/)
{
    llvm::LLVMContext context;

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
