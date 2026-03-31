#include "mutation_campaign.hpp"
#include "mutation_enumeration.hpp"
#include "mutation_operators.hpp"

// Lifted library headers (all from src/lifted/ which is in include path):
#include "abi/all_registers_cc.hpp"
// bb_sync_info_builder is in eval-suite — replicate the trivial inline here
// to avoid a circular dependency (fault-injection → eval-suite → fault-injection).
#include "binary_context.hpp"
#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include "opt.hpp"
#include "pipeline/pipeline.hpp"
#include "pipeline/run_config.hpp"
#include "pipeline/stages/seed_sweep_stage.hpp"
#include "utils.hpp"
#include "verification/bb_sync_info.hpp"
#include "verification/executor.hpp"
#include "verification/jit_executor.hpp"
#include "verification/sentinel_oracle.hpp"
#include "verification/unicorn_executor.hpp"

#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <chrono>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <unordered_map>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
namespace lifted::fault_injection
{

// ── MutantResult ─────────────────────────────────────────────────────────────

double MutantResult::kill_rate() const
{
    if (runs_total == 0)
        return 0.0;
    return static_cast<double>(runs_killed) / static_cast<double>(runs_total);
}

double MutantResult::empirical_difficulty() const
{
    return 1.0 - kill_rate();
}

// ── MutationReport ───────────────────────────────────────────────────────────

double MutationReport::mutation_score() const
{
    if (total_mutants == 0)
        return 0.0;
    return static_cast<double>(killed) / static_cast<double>(total_mutants);
}

double MutationReport::adjusted_score() const
{
    if (total_mutants <= equivalent)
        return 0.0;
    return static_cast<double>(killed) / static_cast<double>(total_mutants - equivalent);
}

void MutationReport::print(std::ostream &os) const
{
    auto pct = [](size_t num, size_t den) -> double
    {
        if (den == 0)
            return 0.0;
        return 100.0 * static_cast<double>(num) / static_cast<double>(den);
    };

    os << "=== MUTATION REPORT: " << func_name << " ===\n";
    os << "Binary: " << binary_stem << "\n";
    os << "Pipeline: post-inline, pre-opt\n";
    os << "Enumerated: " << total_enumerated << " mutation points"
       << "  |  Tested: " << total_mutants << " (budget: " << budget_requested << ")\n";
    os << "Killed: " << killed
       << "  |  Survived: " << survived
       << "  |  Equivalent: " << equivalent
       << "  |  Errors: " << errors << "\n";
    os << std::fixed << std::setprecision(1);
    os << "Mutation Score: " << pct(killed, total_mutants) << "%"
       << "  (adjusted: " << pct(killed, total_mutants - equivalent) << "%)\n";

    // By category
    os << "\nBy Category:\n";
    // Print in canonical order: all enum values
    constexpr MutationCategory all_cats[] = {
        MutationCategory::ARITHMETIC,
        MutationCategory::BITWISE,
        MutationCategory::COMPARISON_NEG,
        MutationCategory::COMPARISON_BDRY,
        MutationCategory::OPERAND_SWAP,
        MutationCategory::DROP_COMPUTATION,
        MutationCategory::CONSTANT_REPL,
        MutationCategory::NEGATE_TRUNC,
    };
    for (auto cat : all_cats)
    {
        auto it = by_category.find(cat);
        if (it == by_category.end() || it->second.second == 0)
            continue;
        auto [k, t] = it->second;
        auto diff = static_difficulty(cat);
        std::string_view diff_name =
            diff == difficulty_t::EASY ? "EASY" : diff == difficulty_t::MEDIUM ? "MEDIUM"
                                                                               : "HARD";
        os << "  " << std::left << std::setw(20) << category_name(cat)
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)"
           << "  [" << diff_name << "]\n";
    }

    // By difficulty
    os << "\nBy Difficulty:\n";
    constexpr difficulty_t all_diffs[] = {
        difficulty_t::EASY, difficulty_t::MEDIUM, difficulty_t::HARD};
    for (auto d : all_diffs)
    {
        auto it = by_difficulty.find(d);
        if (it == by_difficulty.end() || it->second.second == 0)
            continue;
        auto [k, t] = it->second;
        std::string_view dname =
            d == difficulty_t::EASY ? "EASY" : d == difficulty_t::MEDIUM ? "MEDIUM"
                                                                         : "HARD";
        os << "  " << std::left << std::setw(8) << dname
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)\n";
    }

    // By width
    os << "\nBy Width (instruction operand bit width):\n";
    // Print common widths in descending order, then any others
    constexpr unsigned ordered_widths[] = {64, 32, 16, 8, 1};
    for (unsigned w : ordered_widths)
    {
        auto it = by_width_bits.find(w);
        if (it == by_width_bits.end() || it->second.second == 0)
            continue;
        auto [k, t] = it->second;
        std::string label = "i" + std::to_string(w);
        std::string annot = (w == 8 || w == 1) ? " [flag comp.]" : "";
        os << "  " << std::left << std::setw(6) << label
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)" << annot << "\n";
    }
    // Other widths not in the above list
    for (const auto &[w, kt] : by_width_bits)
    {
        bool is_ordered = false;
        for (unsigned ow : ordered_widths)
            if (ow == w)
            {
                is_ordered = true;
                break;
            }
        if (is_ordered || kt.second == 0)
            continue;
        auto [k, t] = kt;
        std::string label = "i" + std::to_string(w);
        os << "  " << std::left << std::setw(6) << label
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)  [other]\n";
    }

    // Survivors
    os << "\nSurvivors:\n";
    bool any_survivors = false;
    for (const auto &r : results)
    {
        if (r.status != MutantStatus::SURVIVED && r.status != MutantStatus::EQUIVALENT)
            continue;
        any_survivors = true;
        // Show category, operator name, and the before→after IR diff.
        // Two lines per survivor: easier to read than a long single line.
        os << "  [" << category_name(r.point.mut->category) << "] "
           << r.point.mut->name << "  (i" << r.point.instruction_width_bits << ")\n";
        os << "    before: " << r.point.instruction_str << "\n";
        os << "    after:  " << r.mutated_str << "\n";
    }
    if (!any_survivors)
        os << "  (none)\n";
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// Wall-clock duration between two steady_clock time points, in milliseconds.
static double duration_ms(std::chrono::steady_clock::time_point start,
                          std::chrono::steady_clock::time_point end)
{
    using namespace std::chrono;
    return static_cast<double>(duration_cast<nanoseconds>(end - start).count()) * 1e-6;
}

// Build the same 2-stage pipeline used by eval_pipeline.cpp (RAW_STRICT profile).
static pipeline::PipelineSpec make_campaign_pipeline(
    const std::string &func_name,
    std::shared_ptr<verification::Executor> src,
    std::shared_ptr<verification::Executor> tgt)
{
    using EF = verification::event_flags;
    using DF = verification::compare_dimension_flags;

    pipeline::RunConfig wide_cfg{
        .seed = 0x1338,
        .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
            {.size_bytes = 0, .value = 0, .inv_prob = 10},
            {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFFull, .inv_prob = 10},
        }),
        .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
            verification::value_constraints_t{.max = 0xFFFF'FFFF'FFFF'FFFFull, .alignment = 8}),
        .bb_limit = 5000,
        .loop_limit = 100,
        .sync_on = EF::BB | EF::MEM_WRITE | EF::EXT_CALL,
        .compare_dims = DF::REG_STATE | DF::MEM_CONTENTS | DF::WRITE_SEQUENCE | DF::BB_TRACE | DF::EXT_CALLS,
    };

    pipeline::RunConfig small_cfg{
        .seed = 0x1337,
        .oracle = verification::sentinel_oracle(std::vector<verification::sentinel_t>{
            {.size_bytes = 0, .value = 0, .inv_prob = 10},
            {.size_bytes = 0, .value = 0xFFFF'FFFF'FFFF'FFFFull, .inv_prob = 10},
        }),
        .gen_factory = std::make_shared<verification::uniform_value_generator_factory>(
            verification::value_constraints_t{.max = 0x10000, .alignment = 1}),
        .bb_limit = 2000,
        .loop_limit = 50,
        .sync_on = EF::BB | EF::MEM_WRITE | EF::EXT_CALL,
        .compare_dims = DF::REG_STATE | DF::MEM_CONTENTS | DF::WRITE_SEQUENCE | DF::BB_TRACE | DF::EXT_CALLS,
    };

    pipeline::PipelineSpec spec;
    spec.name = "mutant[" + func_name + "]";
    spec.executors = {std::move(src), std::move(tgt)};
    spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(wide_cfg, 50));
    spec.stages.push_back(std::make_unique<pipeline::SeedSweepStage>(small_cfg, 100));
    return spec;
}

// ── MutationCampaign::run ─────────────────────────────────────────────────────

llvm::Expected<MutationReport> MutationCampaign::run(
    llvm::LLVMContext &ctx,
    const std::filesystem::path &binary_path,
    const std::string &func_name,
    uint64_t entry_rva,
    Config cfg)
{
    // 1. Parse binary and set up BinaryContext
    auto binary = LIEF::Parser::parse(binary_path.string());
    if (!binary)
        return llvm::make_error<llvm::StringError>(
            "Failed to parse binary: " + binary_path.string(),
            llvm::inconvertibleErrorCode());
    BinaryContext bin_ctx(std::move(binary));

    // 2. Set up lifter (standard, non-polaris)
    auto arch = remill::Arch::Get(ctx, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
    std::string artifact_dir =
        "/tmp/mutation_campaign_" + binary_path.filename().string() + "_" + func_name;
    auto lc = lifter::standard_lifter_config_t::from_standard_linux_binary(
        bin_ctx.binary(), artifact_dir);
    auto callbacks = std::make_unique<lifter::StandardLifterCallbacks>(std::move(lc));
    auto the_lifter_or = lifter::Lifter::create(arch.get(), bin_ctx, callbacks.get());
    if (!the_lifter_or)
        return the_lifter_or.takeError();
    auto &the_lifter = *the_lifter_or;

    // 3. Add annotation and lift
    auto entry_ann = std::make_unique<fnc_annotation_t>();
    entry_ann->cc = &abi::AllRegistersCC::get();
    auto entry_ann_id = bin_ctx.add_annotation(std::move(entry_ann));

    // Timing: campaign covers lift + inlining + baseline + all mutants.
    auto t0_campaign = std::chrono::steady_clock::now();
    auto t0_lift = t0_campaign;

    auto lift_result = the_lifter.lift(entry_rva, entry_ann_id, {.instrument_bb_entry = true});
    if (!lift_result)
        return llvm::make_error<llvm::StringError>(
            "Lift failed: " + llvm::toString(lift_result.takeError()),
            llvm::inconvertibleErrorCode());
    // Record lift duration locally; will be stored in report once report is built.
    double lift_ms = duration_ms(t0_lift, std::chrono::steady_clock::now());

    // 4. Build bb_sync_info and ext_call_info.
    // Replicate eval::make_bb_sync_info inline (avoids eval-suite dependency).
    verification::bb_sync_info_t bb_sync_info;
    {
        bb_sync_info.real_blocks.reserve(lift_result->basic_blocks.size());
        for (const auto &bb : lift_result->basic_blocks)
        {
            if (bb.type != lifter::lifted_bb_t::Type::REAL || !bb.rva_range)
                continue;
            bb_sync_info.real_blocks.push_back({.start = bb.rva_range->start(),
                                                .end = bb.rva_range->end()});
        }
        std::sort(bb_sync_info.real_blocks.begin(), bb_sync_info.real_blocks.end(),
                  [](const auto &a, const auto &b)
                  { return a.start < b.start; });
    }

    verification::UnicornExecutor::ext_call_info_t ext_info;
    {
        // Map bb_id → rva for edge classification
        std::unordered_map<lifter::bb_id_t, uint64_t> bb_id_to_rva;
        for (const auto &bb : lift_result->basic_blocks)
            if (bb.rva_range.has_value())
                bb_id_to_rva[bb.id] = bb.rva_range->start();

        for (const auto &[id, synth] : lift_result->synthetic_blocks)
            if (synth.type == lifter::synthetic_block_info_t::Type::EXTERNAL &&
                synth.dest_addr.has_value())
                ext_info.ext_function_rvas.insert(*synth.dest_addr);

        for (const auto &edge : lift_result->edges)
        {
            auto it = bb_id_to_rva.find(edge.source);
            if (it == bb_id_to_rva.end())
                continue;
            if (edge.type == lifter::edge_t::Type::SYNTHETIC_RECURSIVE_CALL)
                ext_info.recursive_callsite_rvas.insert(it->second);
            else if (edge.type == lifter::edge_t::Type::SYNTHETIC_INDIRECT)
                ext_info.indr_dispatch_block_rvas.insert(it->second);
        }
    }

    // 5. Get the lifted (stitched) function name
    std::string fn_name = lift_result->lifted_function->getName().str();

    // 6. Build M_inline: clone and always_inline so mutants operate on the
    //    fully-inlined IR and every BinaryOperator/ICmpInst is visible.
    auto M_inline = llvm::CloneModule(*lift_result->module);
    opt::always_inline(M_inline.get());
    opt::default_opt(M_inline.get(), llvm::OptimizationLevel::O2);

    utils::output_to_file("/home/atlas/lifted/out/pre_mutation.ll", M_inline.get());

    // 7. Create Unicorn executor (shared across all mutants; native side is
    //    immutable with respect to LLVM mutations).
    auto uc_or = verification::UnicornExecutor::create(
        bin_ctx, std::move(ext_info), entry_rva,
        verification::UnicornExecutor::Flags::NONE,
        std::move(bb_sync_info));
    if (!uc_or)
        return uc_or.takeError();
    auto uc = std::shared_ptr<verification::Executor>(std::move(*uc_or));

    // 8. Baseline run on the unmodified inlined module — must PASS before we
    //    trust any mutation results.
    {
        auto M_base = llvm::CloneModule(*M_inline);
        auto jit_or = verification::JITExecutor::create(std::move(M_base), fn_name);
        if (!jit_or)
            return jit_or.takeError();
        auto jit = std::shared_ptr<verification::Executor>(std::move(*jit_or));

        auto spec = make_campaign_pipeline(fn_name, jit, uc);
        pipeline::Pipeline pl(std::move(spec));
        auto base_report = pl.run(bin_ctx, entry_rva);
        if (!base_report)
            return base_report.takeError();

        if (base_report->total_failures() > 0)
            return llvm::make_error<llvm::StringError>(
                "Baseline run failed (" +
                    std::to_string(base_report->total_failures()) +
                    " divergence(s)) for " + func_name +
                    " — cannot run mutation campaign",
                llvm::inconvertibleErrorCode());
    }

    // 9. Enumerate mutation points in the inlined function
    auto *lifted_fn = M_inline->getFunction(fn_name);
    if (!lifted_fn)
        return llvm::make_error<llvm::StringError>(
            "Cannot find function '" + fn_name + "' in inlined module",
            llvm::inconvertibleErrorCode());

    const auto &operators = all_integer_operators();
    EnumerationConfig enum_cfg;
    enum_cfg.budget = cfg.budget;
    enum_cfg.seed = cfg.seed;
    enum_cfg.allowed_categories = cfg.filter_categories;

    size_t total_enumerated = 0;
    auto points = enumerate_and_sample(*lifted_fn, operators, enum_cfg, &total_enumerated);

    // 10. Initialize report
    MutationReport report;
    report.func_name = func_name;
    report.binary_stem = binary_path.stem().string();
    report.total_enumerated = total_enumerated;
    report.total_mutants = points.size();
    report.budget_requested = cfg.budget;
    report.lift_duration_ms = lift_ms;

    // 11. Run each mutant
    for (auto &point : points)
    {
        // Clone the inlined module for this mutant so mutations are isolated.
        auto M_mut = llvm::CloneModule(*M_inline);
        auto *mut_fn = M_mut->getFunction(fn_name);
        assert(mut_fn && "function must exist in clone");

        auto *instr = get_instruction_at(mut_fn, point.instruction_index);
        if (!instr)
        {
            // Index out of range — shouldn't happen if enumeration was correct.
            MutantResult r;
            r.point = point;
            r.status = MutantStatus::ERROR;
            report.results.push_back(std::move(r));
            ++report.errors;
            continue;
        }

        // Apply mutation; capture IR text of the result before moving the module.
        auto *mut_val = point.mut->op->mutate(instr);
        std::string mutated_str;
        {
            llvm::raw_string_ostream os(mutated_str);
            if (llvm::isa<llvm::Instruction>(mut_val))
            {
                mut_val->print(os);
                os.flush();
                // Strip leading whitespace emitted by LLVM's instruction printer.
                const auto first = mutated_str.find_first_not_of(" \t");
                if (first != std::string::npos)
                    mutated_str = mutated_str.substr(first);
            }
            else
            {
                // Non-instruction Value (e.g. constant or argument from InstrDropper).
                mut_val->printAsOperand(os, /*PrintType=*/true);
                os.flush();
            }
        }

        auto jit_or = verification::JITExecutor::create(std::move(M_mut), fn_name);
        if (!jit_or)
        {
            // JIT compilation failed (e.g. illegal IR after mutation) — treat as error.
            llvm::consumeError(jit_or.takeError());
            MutantResult r;
            r.point = point;
            r.status = MutantStatus::ERROR;
            report.results.push_back(std::move(r));
            ++report.errors;
            continue;
        }
        auto jit = std::shared_ptr<verification::Executor>(std::move(*jit_or));

        auto spec = make_campaign_pipeline(fn_name, jit, uc);
        pipeline::Pipeline pl(std::move(spec));
        auto mut_report = pl.run(bin_ctx, entry_rva);

        MutantResult r;
        r.point = point;
        r.mutated_str = std::move(mutated_str);
        if (!mut_report)
        {
            llvm::consumeError(mut_report.takeError());
            r.status = MutantStatus::ERROR;
            ++report.errors;
        }
        else
        {
            bool any_diverged = false;
            bool any_incomparable = false;
            int first_diverged_stage = -1;

            for (int s = 0; s < static_cast<int>(mut_report->stages.size()); ++s)
            {
                const auto &stage = mut_report->stages[s];
                if (stage.fail_count > 0)
                {
                    any_diverged = true;
                    if (first_diverged_stage < 0)
                        first_diverged_stage = s;
                }
                if (stage.incomparable > 0)
                    any_incomparable = true;
            }

            r.runs_total = mut_report->stages.size();
            r.stage_killed = first_diverged_stage;

            if (any_diverged)
            {
                r.status = MutantStatus::KILLED;
                r.runs_killed = 1;
                ++report.killed;
            }
            else if (any_incomparable)
            {
                r.status = MutantStatus::EQUIVALENT;
                ++report.equivalent;
            }
            else
            {
                r.status = MutantStatus::SURVIVED;
                ++report.survived;
            }
        }

        report.results.push_back(std::move(r));
    }

    // Capture total campaign duration (lift + inlining + baseline + all mutants).
    report.campaign_duration_ms = duration_ms(t0_campaign, std::chrono::steady_clock::now());

    // 12. Build per-category, per-difficulty, and per-width breakdowns.
    for (const auto &r : report.results)
    {
        bool k = (r.status == MutantStatus::KILLED);

        auto &bc = report.by_category[r.point.mut->category];
        ++bc.second;
        if (k)
            ++bc.first;

        auto &bd = report.by_difficulty[static_difficulty(r.point.mut->category)];
        ++bd.second;
        if (k)
            ++bd.first;

        auto &bw = report.by_width_bits[r.point.instruction_width_bits];
        ++bw.second;
        if (k)
            ++bw.first;
    }

    return report;
}

} // namespace lifted::fault_injection
