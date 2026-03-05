#include "eval_pipeline.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include "lifter/lifter_types.hpp"
#include "abi/systemv_x64.hpp"
#include "verification/jit_executor.hpp"
#include "verification/unicorn_executor.hpp"
#include "verification/sentinel_oracle.hpp"
#include "pipeline/pipeline.hpp"
#include "pipeline/stages/seed_sweep_stage.hpp"
#include "utils.hpp"

#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <memory>
#include <set>

namespace lifted::eval
{
    pipeline::PipelineSpec make_default_pipeline(
        const std::string &func_name,
        pipeline::ExecutorPair::Factory make_jit,
        pipeline::ExecutorPair::Factory make_unicorn)
    {
        pipeline::RunConfig wide_cfg{
            .seed = 0x1338,
            .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
                {.size_bytes = 0, .value = 0, .inv_prob = 10},
                {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFF, .inv_prob = 10},
            }),
            .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
                verification::value_constraints_t{.max = 0xFFFF'FFFF'FFFF'FFFF, .alignment = 8}),
            .bb_limit = 10'000,
            .loop_limit = 200,
        };

        pipeline::RunConfig loop_breaker{
            .seed = 0x1337,
            .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
                {.size_bytes = 0, .value = 0, .inv_prob = 10},
                {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFF, .inv_prob = 10},
            }),
            .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
                verification::value_constraints_t{.max = 0x10'000, .alignment = 8}),
            .bb_limit = 10'000,
            .loop_limit = 50,
        };

        pipeline::PipelineSpec spec;
        spec.name = "raw_vs_native[" + func_name + "]";
        spec.executors = {std::move(make_jit), std::move(make_unicorn)};
        spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(wide_cfg, 100));
        spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(loop_breaker, 500));
        return spec;
    }

    // ── lift_and_verify_named ──────────────────────────────────────────────────────

    llvm::Expected<LiftAndVerifyResult>
    lift_and_verify_named(llvm::LLVMContext &context,
                          const std::filesystem::path &path,
                          const std::string &func_name,
                          uint64_t entry_rva,
                          size_t deep_dive_count)
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
            LiftAndVerifyResult r;
            r.lift_failed = true;
            r.lift_error = llvm::toString(lift_result.takeError());
            return r;
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
            std::make_shared<std::unique_ptr<llvm::Module>>(std::move(lift_result->module));

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

        pipeline::Pipeline pl(
            make_default_pipeline(func_name, std::move(make_jit), std::move(make_unicorn)));

        auto report = pl.run(binary, entry_rva);
        if (!report)
            return report.takeError();

        LiftAndVerifyResult result;
        result.report = std::move(*report);

        if (deep_dive_count > 0)
        {
            for (const auto &stage : result.report->stages)
            {
                if (!stage.divergences.empty())
                {
                    auto dd = pl.deep_dive(stage.divergences[0], binary, entry_rva);
                    if (dd)
                        result.deep_dive = std::move(*dd);
                    // A failing deep_dive is non-fatal; the report still has the divergence info.
                    break; // first stage with divergences only
                }
            }
        }

        return result;
    }

    // ── Suite name resolution ──────────────────────────────────────────────────────
    //
    // Each branch is guarded by #ifdef so the library compiles even when no CSV
    // paths were injected at configure time (e.g. standalone builds, unit tests).

    std::optional<std::filesystem::path> resolve_suite_name(const std::string &name)
    {
#ifdef EVAL_SUITE_SYNTHETIC_CSV
        if (name == "synthetic")
            return std::filesystem::path{EVAL_SUITE_SYNTHETIC_CSV};
#endif
#ifdef EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV
        if (name == "tum-small-programs")
            return std::filesystem::path{EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV};
#endif
#ifdef EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV
        if (name == "tum-basic-algorithms")
            return std::filesystem::path{EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV};
#endif
#ifdef EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV
        if (name == "tum-simple-hash-functions")
            return std::filesystem::path{EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV};
#endif
        return std::nullopt;
    }

    std::vector<std::string> known_suite_names()
    {
        std::vector<std::string> names;
#ifdef EVAL_SUITE_SYNTHETIC_CSV
        names.push_back("synthetic");
#endif
#ifdef EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV
        names.push_back("tum-small-programs");
#endif
#ifdef EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV
        names.push_back("tum-basic-algorithms");
#endif
#ifdef EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV
        names.push_back("tum-simple-hash-functions");
#endif
        return names;
    }

} // namespace lifted::eval
