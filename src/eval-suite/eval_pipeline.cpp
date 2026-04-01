#include "eval_pipeline.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include "abi/all_registers_cc.hpp"
#include "bb_sync_info_builder.hpp"
#include "binary_context.hpp"
#include "lifter/lifter.hpp"
#include "lifter/polaris_lifter_callbacks.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include "mutation_enumeration.hpp"
#include "mutation_operators.hpp"
#include "opt.hpp"
#include "pipeline/stages/seed_sweep_stage.hpp"
#include "utils.hpp"
#include "verification/jit_executor.hpp"
#include "verification/sentinel_oracle.hpp"
#include "verification/unicorn_executor.hpp"

#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <unordered_map>

namespace lifted::eval
{
namespace
{
using verification::Executor;

struct LiftArtifacts
{
    std::unique_ptr<BinaryContext> bin_ctx;
    std::optional<lifter::lift_stats_t> lift_stats;
    std::optional<visualization::CfgSnapshot> cfg;
    verification::bb_sync_info_t bb_sync_info;
    verification::UnicornExecutor::ext_call_info_t ext_info;
    std::unique_ptr<llvm::Module> raw_module;
    std::string lifted_function_name;

    explicit LiftArtifacts(std::unique_ptr<BinaryContext> ctx)
        : bin_ctx(std::move(ctx)) {}
};

double duration_ms(std::chrono::steady_clock::time_point start,
                   std::chrono::steady_clock::time_point end)
{
    using namespace std::chrono;
    return static_cast<double>(duration_cast<nanoseconds>(end - start).count()) * 1e-6;
}

void mark_skipped(VerificationPhaseResult &phase, std::string_view reason)
{
    phase.status = PhaseStatus::SKIPPED;
    phase.skip_reason = std::string(reason);
}

void mark_skipped(MutationPhaseResult &phase, std::string_view reason)
{
    phase.status = MutationPhaseStatus::SKIPPED;
    phase.skip_reason = std::string(reason);
}

std::unique_ptr<lifter::LifterCallbacks>
make_lifter_callbacks(BinaryContext &bin_ctx,
                      const std::filesystem::path &path,
                      std::string_view obfuscator,
                      const std::string &func_name)
{
    const std::string artifact_dir =
        "/home/atlas/lifted/out/eval_artifacts/" + path.filename().string() + "_" + func_name;

    if (obfuscator == "polaris")
    {
        auto cfg = lifter::polaris_lifter_config_t::from_polaris_linux_binary(
            bin_ctx.binary(), artifact_dir);
        return std::make_unique<lifter::PolarisLifterCallbacks>(std::move(cfg));
    }

    auto cfg = lifter::standard_lifter_config_t::from_standard_linux_binary(
        bin_ctx.binary(), artifact_dir);
    return std::make_unique<lifter::StandardLifterCallbacks>(std::move(cfg));
}

llvm::Expected<LiftArtifacts>
lift_artifacts(llvm::LLVMContext &context,
               const std::filesystem::path &path,
               const std::string &func_name,
               uint64_t entry_rva,
               std::string_view obfuscator)
{
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchAMD64);

    std::unique_ptr<LIEF::Binary> binary = LIEF::Parser::parse(path);
    if (!binary)
        return llvm::make_error<llvm::StringError>(
            "Failed to parse binary: " + path.string(),
            llvm::inconvertibleErrorCode());

    auto bin_ctx = std::make_unique<BinaryContext>(std::move(binary));
    auto callbacks = make_lifter_callbacks(*bin_ctx, path, obfuscator, func_name);
    auto the_lifter_or = lifter::Lifter::create(arch.get(), *bin_ctx, callbacks.get());
    if (!the_lifter_or)
        return the_lifter_or.takeError();
    auto &the_lifter = *the_lifter_or;

    auto entry_ann = std::make_unique<fnc_annotation_t>();
    entry_ann->cc = &abi::AllRegistersCC::get();
    annotation_id_t entry_annotation_id = bin_ctx->add_annotation(std::move(entry_ann));

    auto lift_result = the_lifter.lift(entry_rva, entry_annotation_id, {.instrument_bb_entry = true});
    if (!lift_result)
        return lift_result.takeError();

    LiftArtifacts artifacts(std::move(bin_ctx));
    artifacts.lift_stats = std::move(lift_result->stats);
    artifacts.cfg = visualization::make_cfg_snapshot(*lift_result, *artifacts.bin_ctx, entry_rva, func_name);
    artifacts.bb_sync_info = eval::make_bb_sync_info(lift_result->basic_blocks);
    artifacts.lifted_function_name = lift_result->lifted_function->getName().str();
    artifacts.raw_module = std::move(lift_result->module);

    std::unordered_map<lifter::bb_id_t, uint64_t> bb_id_to_rva;
    for (const auto &bb : lift_result->basic_blocks)
        if (bb.rva_range.has_value())
            bb_id_to_rva[bb.id] = bb.rva_range->start();

    for (const auto &[id, synth] : lift_result->synthetic_blocks)
        if (synth.type == lifter::synthetic_block_info_t::Type::EXTERNAL &&
            synth.dest_addr.has_value())
            artifacts.ext_info.ext_function_rvas.insert(*synth.dest_addr);

    for (const auto &edge : lift_result->edges)
    {
        auto it = bb_id_to_rva.find(edge.source);
        if (it == bb_id_to_rva.end())
            continue;
        if (edge.type == lifter::edge_t::Type::SYNTHETIC_RECURSIVE_CALL)
            artifacts.ext_info.recursive_callsite_rvas.insert(it->second);
        else if (edge.type == lifter::edge_t::Type::SYNTHETIC_INDIRECT)
            artifacts.ext_info.indr_dispatch_block_rvas.insert(it->second);
    }

    return artifacts;
}

llvm::Expected<std::shared_ptr<Executor>>
make_raw_jit(const LiftArtifacts &artifacts)
{
    auto jit_or = verification::JITExecutor::create(
        llvm::CloneModule(*artifacts.raw_module), artifacts.lifted_function_name);
    if (!jit_or)
        return jit_or.takeError();
    return std::shared_ptr<Executor>(std::move(*jit_or));
}

llvm::Expected<std::shared_ptr<Executor>>
make_opt_jit(const llvm::Module &module, const std::string &lifted_function_name)
{
    auto jit_or = verification::JITExecutor::create(
        llvm::CloneModule(module), lifted_function_name);
    if (!jit_or)
        return jit_or.takeError();
    return std::shared_ptr<Executor>(std::move(*jit_or));
}

llvm::Expected<std::shared_ptr<Executor>>
make_unicorn(LiftArtifacts &artifacts, uint64_t entry_rva)
{
    auto uc_or = verification::UnicornExecutor::create(
        *artifacts.bin_ctx, std::move(artifacts.ext_info), entry_rva,
        verification::UnicornExecutor::Flags::NONE, std::move(artifacts.bb_sync_info));
    if (!uc_or)
        return uc_or.takeError();
    return std::shared_ptr<Executor>(std::move(*uc_or));
}

VerificationPhaseResult run_phase(BinaryContext &bin_ctx,
                                  uint64_t entry_rva,
                                  const std::string &func_name,
                                  std::shared_ptr<Executor> src,
                                  std::shared_ptr<Executor> tgt,
                                  PipelineCheckpointProfile profile,
                                  size_t deep_dive_count)
{
    VerificationPhaseResult phase;
    pipeline::Pipeline pl(make_default_pipeline(func_name, std::move(src), std::move(tgt), profile));

    auto report = pl.run(bin_ctx, entry_rva);
    if (!report)
    {
        phase.status = PhaseStatus::ERROR;
        phase.error = llvm::toString(report.takeError());
        return phase;
    }

    phase.report = std::move(*report);
    phase.status = phase.report->total_failures() == 0 ? PhaseStatus::PASS : PhaseStatus::FAIL;

    if (deep_dive_count == 0)
        return phase;

    for (const auto &stage : phase.report->stages)
    {
        if (stage.divergences.empty())
            continue;
        auto dd = pl.deep_dive(stage.divergences[0], bin_ctx, entry_rva);
        if (dd)
            phase.deep_dive = std::move(*dd);
        else
            llvm::consumeError(dd.takeError());
        break;
    }

    return phase;
}

std::unique_ptr<llvm::Module>
build_optimized_module(const LiftArtifacts &artifacts)
{
    auto opt_module = llvm::CloneModule(*artifacts.raw_module);
    opt::always_inline(opt_module.get());
    opt::default_opt(opt_module.get(), llvm::OptimizationLevel::O2);
    return opt_module;
}

llvm::Expected<fault_injection::MutationReport>
run_mutation_campaign(BinaryContext &bin_ctx,
                      const std::filesystem::path &binary_path,
                      uint64_t entry_rva,
                      const std::string &report_func_name,
                      const std::string &lifted_function_name,
                      const llvm::Module &optimized_module,
                      const fault_injection::MutationCampaignConfig &cfg,
                      double lift_duration_ms)
{
    auto t0_campaign = std::chrono::steady_clock::now();

    auto baseline_module = llvm::CloneModule(optimized_module);
    auto *baseline_fn = baseline_module->getFunction(lifted_function_name);
    if (!baseline_fn)
        return llvm::make_error<llvm::StringError>(
            "Cannot find function '" + lifted_function_name + "' in optimized module",
            llvm::inconvertibleErrorCode());

    const auto &operators = fault_injection::all_integer_operators();
    fault_injection::EnumerationConfig enum_cfg;
    enum_cfg.budget = cfg.budget;
    enum_cfg.seed = cfg.seed;
    enum_cfg.allowed_categories = cfg.filter_categories;

    size_t total_enumerated = 0;
    auto points = fault_injection::enumerate_and_sample(
        *baseline_fn, operators, enum_cfg, &total_enumerated);

    auto baseline_jit_or = verification::JITExecutor::create(
        std::move(baseline_module), lifted_function_name);
    if (!baseline_jit_or)
        return baseline_jit_or.takeError();
    auto baseline_jit = std::shared_ptr<Executor>(std::move(*baseline_jit_or));

    fault_injection::MutationReport report;
    report.func_name = report_func_name;
    report.binary_stem = binary_path.stem().string();
    report.total_enumerated = total_enumerated;
    report.total_mutants = points.size();
    report.budget_requested = cfg.budget;
    report.lift_duration_ms = lift_duration_ms;

    for (auto &point : points)
    {
        auto mutant_module = llvm::CloneModule(optimized_module);
        auto *mut_fn = mutant_module->getFunction(lifted_function_name);
        if (!mut_fn)
            return llvm::make_error<llvm::StringError>(
                "Cannot find function '" + lifted_function_name + "' in mutant module",
                llvm::inconvertibleErrorCode());

        auto *instr = fault_injection::get_instruction_at(mut_fn, point.instruction_index);
        if (!instr)
        {
            fault_injection::MutantResult r;
            r.point = point;
            r.status = fault_injection::MutantStatus::ERROR;
            report.results.push_back(std::move(r));
            ++report.errors;
            continue;
        }

        auto *mut_val = point.mut->op->mutate(instr);
        std::string mutated_str;
        {
            llvm::raw_string_ostream os(mutated_str);
            if (llvm::isa<llvm::Instruction>(mut_val))
            {
                mut_val->print(os);
                os.flush();
                const auto first = mutated_str.find_first_not_of(" \t");
                if (first != std::string::npos)
                    mutated_str = mutated_str.substr(first);
            }
            else
            {
                mut_val->printAsOperand(os, /*PrintType=*/true);
                os.flush();
            }
        }

        auto mutant_jit_or = verification::JITExecutor::create(
            std::move(mutant_module), lifted_function_name);

        fault_injection::MutantResult r;
        r.point = point;
        r.mutated_str = std::move(mutated_str);
        if (!mutant_jit_or)
        {
            llvm::consumeError(mutant_jit_or.takeError());
            r.status = fault_injection::MutantStatus::ERROR;
            report.results.push_back(std::move(r));
            ++report.errors;
            continue;
        }

        auto mutant_jit = std::shared_ptr<Executor>(std::move(*mutant_jit_or));
        auto phase = run_phase(bin_ctx, entry_rva, report_func_name,
                               baseline_jit, mutant_jit,
                               PipelineCheckpointProfile::OPTIMIZED_RELAXED,
                               /*deep_dive_count=*/0);

        r.runs_total = phase.report ? phase.report->stages.size() : 0;
        if (phase.status == PhaseStatus::ERROR)
        {
            r.status = fault_injection::MutantStatus::ERROR;
            ++report.errors;
            report.results.push_back(std::move(r));
            continue;
        }

        bool any_diverged = false;
        bool any_incomparable = false;
        int first_diverged_stage = -1;
        for (int s = 0; s < static_cast<int>(phase.report->stages.size()); ++s)
        {
            const auto &stage = phase.report->stages[s];
            if (stage.fail_count > 0)
            {
                any_diverged = true;
                if (first_diverged_stage < 0)
                    first_diverged_stage = s;
            }
            if (stage.incomparable > 0)
                any_incomparable = true;
        }

        r.stage_killed = first_diverged_stage;
        if (any_diverged)
        {
            r.status = fault_injection::MutantStatus::KILLED;
            r.runs_killed = 1;
            ++report.killed;
        }
        else if (any_incomparable)
        {
            r.status = fault_injection::MutantStatus::EQUIVALENT;
            ++report.equivalent;
        }
        else
        {
            r.status = fault_injection::MutantStatus::SURVIVED;
            ++report.survived;
        }

        report.results.push_back(std::move(r));
    }

    report.campaign_duration_ms = duration_ms(t0_campaign, std::chrono::steady_clock::now());

    for (const auto &r : report.results)
    {
        const bool killed = r.status == fault_injection::MutantStatus::KILLED;

        auto &by_category = report.by_category[r.point.mut->category];
        ++by_category.second;
        if (killed)
            ++by_category.first;

        auto &by_difficulty = report.by_difficulty[
            fault_injection::static_difficulty(r.point.mut->category)];
        ++by_difficulty.second;
        if (killed)
            ++by_difficulty.first;

        auto &by_width = report.by_width_bits[r.point.instruction_width_bits];
        ++by_width.second;
        if (killed)
            ++by_width.first;
    }

    return report;
}
} // namespace

bool FullPipelineResult::raw_pass() const
{
    return !lift_failed && raw_vs_native && raw_vs_native->total_failures() == 0;
}

bool FullPipelineResult::opt_pass() const
{
    if (!opt_transform_error.empty())
        return false;
    if (!opt_vs_raw)
        return true;
    return opt_vs_raw->total_failures() == 0;
}

bool FullPipelineResult::full_pass() const
{
    return raw_pass() && opt_pass();
}

bool VerificationPhaseResult::passed() const
{
    return status == PhaseStatus::PASS;
}

bool MutationPhaseResult::executed() const
{
    return status == MutationPhaseStatus::RUN && report.has_value();
}

size_t EvaluationRecord::bbs_total() const
{
    return lift_stats ? lift_stats->bbs_total : 0;
}

const char *phase_status_name(PhaseStatus status)
{
    switch (status)
    {
    case PhaseStatus::NOT_RUN:
        return "NOT_RUN";
    case PhaseStatus::PASS:
        return "PASS";
    case PhaseStatus::FAIL:
        return "FAIL";
    case PhaseStatus::ERROR:
        return "ERROR";
    case PhaseStatus::SKIPPED:
        return "SKIPPED";
    }
    return "UNKNOWN";
}

const char *mutation_phase_status_name(MutationPhaseStatus status)
{
    switch (status)
    {
    case MutationPhaseStatus::NOT_REQUESTED:
        return "NOT_REQUESTED";
    case MutationPhaseStatus::RUN:
        return "RUN";
    case MutationPhaseStatus::SKIPPED:
        return "SKIPPED";
    case MutationPhaseStatus::ERROR:
        return "ERROR";
    }
    return "UNKNOWN";
}

pipeline::PipelineSpec make_default_pipeline(
    const std::string &func_name,
    std::shared_ptr<verification::Executor> src,
    std::shared_ptr<verification::Executor> tgt,
    PipelineCheckpointProfile profile)
{
    const auto apply_profile = [profile](pipeline::RunConfig &cfg)
    {
        using EF = verification::event_flags;
        using DF = verification::compare_dimension_flags;
        switch (profile)
        {
        case PipelineCheckpointProfile::RAW_STRICT:
            cfg.sync_on = EF::BB | EF::MEM_WRITE | EF::EXT_CALL;
            cfg.compare_dims =
                DF::REG_STATE | DF::MEM_CONTENTS | DF::WRITE_SEQUENCE |
                DF::BB_TRACE | DF::EXT_CALLS;
            break;
        case PipelineCheckpointProfile::OPTIMIZED_RELAXED:
            cfg.sync_on = EF::EXT_CALL;
            cfg.compare_dims =
                DF::REG_STATE | DF::MEM_CONTENTS | DF::EXT_CALLS;
            break;
        }
    };

    pipeline::RunConfig wide_cfg{
        .seed = 0x1338,
        .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
            {.size_bytes = 0, .value = 0, .inv_prob = 10},
            {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFF, .inv_prob = 10},
        }),
        .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
            verification::value_constraints_t{.max = 0xFFFF'FFFF'FFFF'FFFF, .alignment = 8}),
        .bb_limit = 5000,
        .loop_limit = 100,
    };
    apply_profile(wide_cfg);

    pipeline::RunConfig small_cfg{
        .seed = 0x1337,
        .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
            {.size_bytes = 0, .value = 0, .inv_prob = 10},
            {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFF, .inv_prob = 10},
        }),
        .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
            verification::value_constraints_t{.max = 0x10000, .alignment = 1}),
        .bb_limit = 2000,
        .loop_limit = 50,
    };
    apply_profile(small_cfg);

    pipeline::PipelineSpec spec;
    spec.name = "raw_vs_native[" + func_name + "]";
    spec.executors = {std::move(src), std::move(tgt)};
    spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(wide_cfg, 50));
    spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(small_cfg, 100));
    return spec;
}

llvm::Expected<LiftAndVerifyResult>
lift_and_verify_named(llvm::LLVMContext &context,
                      const std::filesystem::path &path,
                      const std::string &func_name,
                      uint64_t entry_rva,
                      size_t deep_dive_count,
                      std::string_view obfuscator)
{
    auto artifacts_or = lift_artifacts(context, path, func_name, entry_rva, obfuscator);
    if (!artifacts_or)
    {
        LiftAndVerifyResult r;
        r.lift_failed = true;
        r.lift_error = llvm::toString(artifacts_or.takeError());
        return r;
    }

    auto artifacts = std::move(*artifacts_or);
    utils::output_to_file("/home/atlas/lifted/out/lifter_outputs/" + path.filename().string() + "_" + func_name + ".ll",
                          artifacts.raw_module.get());

    auto jit_or = make_raw_jit(artifacts);
    if (!jit_or)
        return jit_or.takeError();
    auto uc_or = make_unicorn(artifacts, entry_rva);
    if (!uc_or)
        return uc_or.takeError();

    pipeline::Pipeline pl(make_default_pipeline(func_name, *jit_or, *uc_or));
    auto report = pl.run(*artifacts.bin_ctx, entry_rva);
    if (!report)
        return report.takeError();

    LiftAndVerifyResult result;
    result.report = std::move(*report);
    result.cfg = std::move(artifacts.cfg);
    result.lift_stats = std::move(artifacts.lift_stats);
    if (deep_dive_count > 0)
    {
        for (const auto &stage : result.report->stages)
        {
            if (stage.divergences.empty())
                continue;
            auto dd = pl.deep_dive(stage.divergences[0], *artifacts.bin_ctx, entry_rva);
            if (dd)
                result.deep_dive = std::move(*dd);
            else
                llvm::consumeError(dd.takeError());
            break;
        }
    }

    return result;
}

llvm::Expected<FullPipelineResult>
lift_and_verify_full_named(llvm::LLVMContext &context,
                           const std::filesystem::path &path,
                           const std::string &func_name,
                           uint64_t entry_rva,
                           size_t deep_dive_count,
                           std::string_view obfuscator)
{
    auto artifacts_or = lift_artifacts(context, path, func_name, entry_rva, obfuscator);
    if (!artifacts_or)
    {
        FullPipelineResult r;
        r.lift_failed = true;
        r.lift_error = llvm::toString(artifacts_or.takeError());
        return r;
    }

    auto artifacts = std::move(*artifacts_or);
    auto raw_jit_or = make_raw_jit(artifacts);
    if (!raw_jit_or)
        return raw_jit_or.takeError();
    auto uc_or = make_unicorn(artifacts, entry_rva);
    if (!uc_or)
        return uc_or.takeError();

    pipeline::Pipeline p1(make_default_pipeline(func_name, *raw_jit_or, *uc_or));
    auto report1 = p1.run(*artifacts.bin_ctx, entry_rva);
    if (!report1)
        return report1.takeError();

    FullPipelineResult result;
    result.raw_vs_native = std::move(*report1);
    result.cfg = std::move(artifacts.cfg);
    result.lift_stats = std::move(artifacts.lift_stats);

    if (deep_dive_count > 0)
    {
        for (const auto &stage : result.raw_vs_native->stages)
        {
            if (stage.divergences.empty())
                continue;
            auto dd = p1.deep_dive(stage.divergences[0], *artifacts.bin_ctx, entry_rva);
            if (dd)
                result.raw_vs_native_dive = std::move(*dd);
            else
                llvm::consumeError(dd.takeError());
            break;
        }
    }

    if (result.raw_vs_native->total_failures() > 0)
        return result;

    auto opt_module = build_optimized_module(artifacts);
    auto opt_jit_or = make_opt_jit(*opt_module, artifacts.lifted_function_name);
    if (!opt_jit_or)
    {
        result.opt_transform_error = llvm::toString(opt_jit_or.takeError());
        return result;
    }

    pipeline::Pipeline p2(make_default_pipeline(
        func_name, *raw_jit_or, *opt_jit_or, PipelineCheckpointProfile::OPTIMIZED_RELAXED));
    auto report2 = p2.run(*artifacts.bin_ctx, entry_rva);
    if (!report2)
        return report2.takeError();

    result.opt_vs_raw = std::move(*report2);
    if (deep_dive_count > 0)
    {
        for (const auto &stage : result.opt_vs_raw->stages)
        {
            if (stage.divergences.empty())
                continue;
            auto dd = p2.deep_dive(stage.divergences[0], *artifacts.bin_ctx, entry_rva);
            if (dd)
                result.opt_vs_raw_dive = std::move(*dd);
            else
                llvm::consumeError(dd.takeError());
            break;
        }
    }

    return result;
}

llvm::Expected<EvaluationRecord>
run_evaluation_named(llvm::LLVMContext &context,
                     const std::filesystem::path &path,
                     const std::string &func_name,
                     uint64_t entry_rva,
                     const EvaluationConfig &config)
{
    EvaluationRecord result;

    const bool need_raw = config.run_raw_vs_native || config.run_opt_vs_raw ||
                          config.run_opt_selftest || config.run_mutation;
    const bool need_opt = config.run_opt_vs_raw || config.run_opt_selftest ||
                          config.run_mutation;
    const bool need_selftest = config.run_opt_selftest || config.run_mutation;

    auto artifacts_or = lift_artifacts(context, path, func_name, entry_rva, config.obfuscator);
    if (!artifacts_or)
    {
        result.lift_failed = true;
        result.lift_error = llvm::toString(artifacts_or.takeError());
        if (need_raw)
            mark_skipped(result.raw_vs_native, "lift failed");
        if (need_opt)
            mark_skipped(result.opt_vs_raw, "lift failed");
        if (need_selftest)
            mark_skipped(result.opt_selftest, "lift failed");
        if (config.run_mutation)
            mark_skipped(result.mutation, "lift failed");
        return result;
    }

    auto artifacts = std::move(*artifacts_or);
    result.lift_stats = artifacts.lift_stats;
    result.cfg = artifacts.cfg;

    std::shared_ptr<Executor> raw_jit;
    if (need_raw)
    {
        auto raw_jit_or = make_raw_jit(artifacts);
        if (!raw_jit_or)
        {
            result.raw_vs_native.status = PhaseStatus::ERROR;
            result.raw_vs_native.error = llvm::toString(raw_jit_or.takeError());
            if (need_opt)
                mark_skipped(result.opt_vs_raw, "raw JIT setup failed");
            if (need_selftest)
                mark_skipped(result.opt_selftest, "raw JIT setup failed");
            if (config.run_mutation)
                mark_skipped(result.mutation, "raw JIT setup failed");
            return result;
        }
        raw_jit = *raw_jit_or;

        auto uc_or = make_unicorn(artifacts, entry_rva);
        if (!uc_or)
        {
            result.raw_vs_native.status = PhaseStatus::ERROR;
            result.raw_vs_native.error = llvm::toString(uc_or.takeError());
            if (need_opt)
                mark_skipped(result.opt_vs_raw, "native executor setup failed");
            if (need_selftest)
                mark_skipped(result.opt_selftest, "native executor setup failed");
            if (config.run_mutation)
                mark_skipped(result.mutation, "native executor setup failed");
            return result;
        }

        result.raw_vs_native = run_phase(
            *artifacts.bin_ctx, entry_rva, func_name, raw_jit, *uc_or,
            PipelineCheckpointProfile::RAW_STRICT, config.deep_dive_count);
    }

    if (!need_raw)
        mark_skipped(result.raw_vs_native, "disabled");

    if (!need_opt)
    {
        mark_skipped(result.opt_vs_raw, "disabled");
        if (need_selftest)
            mark_skipped(result.opt_selftest, "disabled");
        if (config.run_mutation)
            mark_skipped(result.mutation, "disabled");
        return result;
    }

    if (!result.raw_vs_native.passed())
    {
        mark_skipped(result.opt_vs_raw, "raw/native did not pass");
        if (need_selftest)
            mark_skipped(result.opt_selftest, "raw/native did not pass");
        if (config.run_mutation)
            mark_skipped(result.mutation, "raw/native did not pass");
        return result;
    }

    auto opt_module = build_optimized_module(artifacts);
    auto opt_jit_or = make_opt_jit(*opt_module, artifacts.lifted_function_name);
    if (!opt_jit_or)
    {
        result.opt_vs_raw.status = PhaseStatus::ERROR;
        result.opt_vs_raw.error = llvm::toString(opt_jit_or.takeError());
        if (need_selftest)
            mark_skipped(result.opt_selftest, "optimized artifact setup failed");
        if (config.run_mutation)
            mark_skipped(result.mutation, "optimized artifact setup failed");
        return result;
    }

    result.opt_vs_raw = run_phase(
        *artifacts.bin_ctx, entry_rva, func_name, raw_jit, *opt_jit_or,
        PipelineCheckpointProfile::OPTIMIZED_RELAXED, config.deep_dive_count);

    if (!need_selftest)
    {
        mark_skipped(result.opt_selftest, "disabled");
        if (config.run_mutation)
            mark_skipped(result.mutation, "disabled");
        return result;
    }

    if (!result.opt_vs_raw.passed())
    {
        mark_skipped(result.opt_selftest, "o2/raw did not pass");
        if (config.run_mutation)
            mark_skipped(result.mutation, "o2/raw did not pass");
        return result;
    }

    auto opt_self_src_or = make_opt_jit(*opt_module, artifacts.lifted_function_name);
    if (!opt_self_src_or)
    {
        result.opt_selftest.status = PhaseStatus::ERROR;
        result.opt_selftest.error = llvm::toString(opt_self_src_or.takeError());
        if (config.run_mutation)
            mark_skipped(result.mutation, "o2 self-test setup failed");
        return result;
    }
    auto opt_self_tgt_or = make_opt_jit(*opt_module, artifacts.lifted_function_name);
    if (!opt_self_tgt_or)
    {
        result.opt_selftest.status = PhaseStatus::ERROR;
        result.opt_selftest.error = llvm::toString(opt_self_tgt_or.takeError());
        if (config.run_mutation)
            mark_skipped(result.mutation, "o2 self-test setup failed");
        return result;
    }

    result.opt_selftest = run_phase(
        *artifacts.bin_ctx, entry_rva, func_name, *opt_self_src_or, *opt_self_tgt_or,
        PipelineCheckpointProfile::OPTIMIZED_RELAXED, config.deep_dive_count);

    if (!config.run_mutation)
    {
        mark_skipped(result.mutation, "disabled");
        return result;
    }

    if (!result.opt_selftest.passed())
    {
        mark_skipped(result.mutation, "o2 self-test did not pass");
        return result;
    }

    auto mutation_or = run_mutation_campaign(
        *artifacts.bin_ctx, path, entry_rva, func_name, artifacts.lifted_function_name,
        *opt_module, config.mutation_config,
        result.lift_stats ? result.lift_stats->total_time_ms : 0.0);
    if (!mutation_or)
    {
        result.mutation.status = MutationPhaseStatus::ERROR;
        result.mutation.error = llvm::toString(mutation_or.takeError());
        return result;
    }

    result.mutation.status = MutationPhaseStatus::RUN;
    result.mutation.report = std::move(*mutation_or);
    return result;
}



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
#ifdef EVAL_SUITE_GNU_COREUTILS_CSV
    if (name == "gnu-coreutils")
        return std::filesystem::path{EVAL_SUITE_GNU_COREUTILS_CSV};
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
#ifdef EVAL_SUITE_GNU_COREUTILS_CSV
    names.push_back("gnu-coreutils");
#endif
    return names;
}

} // namespace lifted::eval
