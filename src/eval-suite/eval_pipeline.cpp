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
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
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

std::unique_ptr<LIEF::Binary> parse_binary_serialized(const std::filesystem::path &path)
{
    static std::mutex parse_mutex;
    // LIEF parser setup races on global logger registration under concurrent first-use.
    // Serialize binary parsing so lifted-eval can keep the heavier lift/verify work parallel.
    std::lock_guard<std::mutex> lock(parse_mutex);
    return LIEF::Parser::parse(path);
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

void mark_skipped(Eg3ProfileResult &profile, std::string_view reason)
{
    mark_skipped(profile.selftest, reason);
    mark_skipped(profile.mutation, reason);
}

llvm::Error make_string_error(const std::string &message)
{
    return llvm::make_error<llvm::StringError>(message, llvm::inconvertibleErrorCode());
}

std::string json_path(const std::string &path, llvm::StringRef field)
{
    return path.empty() ? field.str() : path + "." + field.str();
}

const char *lift_skip_reason(LiftStatus status)
{
    switch (status)
    {
    case LiftStatus::PASS:
        return "";
    case LiftStatus::ERROR:
        return "lift failed";
    case LiftStatus::TIMEOUT:
        return "lift timeout";
    }
    return "lift failed";
}

bool needs_raw_phase(const EvaluationConfig &config)
{
    return config.run_raw_vs_native || config.run_opt_vs_raw || config.run_eg3_strict ||
           config.run_eg3_relaxed;
}

bool needs_opt_phase(const EvaluationConfig &config)
{
    return config.run_opt_vs_raw || config.run_eg3_strict || config.run_eg3_relaxed;
}

EvaluationRecord make_base_record(const EvaluationConfig &config)
{
    EvaluationRecord result;
    result.eg3_strict.profile = config.eg3_strict_profile;
    result.eg3_relaxed.profile = config.eg3_relaxed_profile;
    if (!needs_raw_phase(config))
        mark_skipped(result.raw_vs_native, "disabled");
    if (!needs_opt_phase(config))
        mark_skipped(result.opt_vs_raw, "disabled");
    if (!config.run_eg3_strict)
        mark_skipped(result.eg3_strict, "disabled");
    if (!config.run_eg3_relaxed)
        mark_skipped(result.eg3_relaxed, "disabled");
    return result;
}

void skip_requested_eg3(EvaluationRecord &result,
                        const EvaluationConfig &config,
                        std::string_view reason)
{
    if (config.run_eg3_strict)
        mark_skipped(result.eg3_strict, reason);
    if (config.run_eg3_relaxed)
        mark_skipped(result.eg3_relaxed, reason);
}

llvm::Expected<const llvm::json::Object *> require_object(const llvm::json::Value &value,
                                                          const std::string &path)
{
    if (const auto *obj = value.getAsObject())
        return obj;
    return make_string_error(path + " must be an object");
}

llvm::Expected<const llvm::json::Array *> require_array(const llvm::json::Value &value,
                                                        const std::string &path)
{
    if (const auto *arr = value.getAsArray())
        return arr;
    return make_string_error(path + " must be an array");
}

llvm::Expected<std::string> parse_string_value(const llvm::json::Value &value,
                                               const std::string &path)
{
    if (auto text = value.getAsString())
        return text->str();
    return make_string_error(path + " must be a string");
}

llvm::Expected<uint64_t> parse_uint_value(const llvm::json::Value &value,
                                          const std::string &path)
{
    if (auto u = value.getAsUINT64())
        return *u;
    if (auto i = value.getAsInteger())
    {
        if (*i < 0)
            return make_string_error(path + " must be non-negative");
        return static_cast<uint64_t>(*i);
    }
    return make_string_error(path + " must be an unsigned integer");
}

llvm::Expected<size_t> parse_size_value(const llvm::json::Value &value,
                                        const std::string &path)
{
    auto parsed = parse_uint_value(value, path);
    if (!parsed)
        return parsed.takeError();
    return static_cast<size_t>(*parsed);
}

llvm::Expected<double> parse_double_value(const llvm::json::Value &value,
                                          const std::string &path)
{
    if (auto number = value.getAsNumber())
        return *number;
    return make_string_error(path + " must be a number");
}

template <typename T, typename Parser>
llvm::Expected<T> parse_required_field(const llvm::json::Object &obj,
                                       llvm::StringRef key,
                                       const std::string &path,
                                       Parser parser)
{
    const llvm::json::Value *value = obj.get(key);
    if (!value)
        return make_string_error(json_path(path, key) + " is required");
    return parser(*value, json_path(path, key));
}

template <typename T, typename Parser>
llvm::Expected<std::optional<T>> parse_optional_field(const llvm::json::Object &obj,
                                                      llvm::StringRef key,
                                                      const std::string &path,
                                                      Parser parser)
{
    const llvm::json::Value *value = obj.get(key);
    if (!value)
        return std::optional<T>{};
    auto parsed = parser(*value, json_path(path, key));
    if (!parsed)
        return parsed.takeError();
    return std::optional<T>(std::move(*parsed));
}

llvm::Expected<uint64_t> parse_uint_key(llvm::StringRef key, const std::string &path)
{
    uint64_t value = 0;
    if (key.getAsInteger(10, value))
        return make_string_error(path + " must be an unsigned integer key");
    return value;
}

const char *exit_type_name(verification::exit_type type)
{
    switch (type)
    {
    case verification::exit_type::NATURAL_EXIT:
        return "NATURAL_EXIT";
    case verification::exit_type::EXCEPTION:
        return "EXCEPTION";
    case verification::exit_type::MISSING_BLOCK:
        return "MISSING_BLOCK";
    case verification::exit_type::CHECKPOINT_MISMATCH:
        return "CHECKPOINT_MISMATCH";
    case verification::exit_type::LAST_CHECKPOINT_REACHED:
        return "LAST_CHECKPOINT_REACHED";
    case verification::exit_type::LOOP_LIMIT:
        return "LOOP_LIMIT";
    case verification::exit_type::BB_LIMIT:
        return "BB_LIMIT";
    }
    return "UNKNOWN";
}

llvm::Expected<verification::exit_type> parse_exit_type_name(llvm::StringRef name,
                                                             const std::string &path)
{
    using ExitType = verification::exit_type;
    if (name == "NATURAL_EXIT")
        return ExitType::NATURAL_EXIT;
    if (name == "EXCEPTION")
        return ExitType::EXCEPTION;
    if (name == "MISSING_BLOCK")
        return ExitType::MISSING_BLOCK;
    if (name == "CHECKPOINT_MISMATCH")
        return ExitType::CHECKPOINT_MISMATCH;
    if (name == "LAST_CHECKPOINT_REACHED")
        return ExitType::LAST_CHECKPOINT_REACHED;
    if (name == "LOOP_LIMIT")
        return ExitType::LOOP_LIMIT;
    if (name == "BB_LIMIT")
        return ExitType::BB_LIMIT;
    return make_string_error(path + " has unknown exit type '" + name.str() + "'");
}

llvm::Expected<LiftStatus> parse_lift_status_value(const llvm::json::Value &value,
                                                   const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "PASS")
        return LiftStatus::PASS;
    if (*text == "ERROR")
        return LiftStatus::ERROR;
    if (*text == "TIMEOUT")
        return LiftStatus::TIMEOUT;
    return make_string_error(path + " has unknown lift status '" + *text + "'");
}

llvm::Expected<PhaseStatus> parse_phase_status_value(const llvm::json::Value &value,
                                                     const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "NOT_RUN")
        return PhaseStatus::NOT_RUN;
    if (*text == "PASS")
        return PhaseStatus::PASS;
    if (*text == "FAIL")
        return PhaseStatus::FAIL;
    if (*text == "ERROR")
        return PhaseStatus::ERROR;
    if (*text == "SKIPPED")
        return PhaseStatus::SKIPPED;
    return make_string_error(path + " has unknown phase status '" + *text + "'");
}

llvm::Expected<MutationPhaseStatus> parse_mutation_phase_status_value(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "NOT_REQUESTED")
        return MutationPhaseStatus::NOT_REQUESTED;
    if (*text == "RUN")
        return MutationPhaseStatus::RUN;
    if (*text == "SKIPPED")
        return MutationPhaseStatus::SKIPPED;
    if (*text == "ERROR")
        return MutationPhaseStatus::ERROR;
    return make_string_error(path + " has unknown mutation phase status '" + *text + "'");
}

llvm::Expected<PipelineCheckpointProfile> parse_checkpoint_profile_value(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "raw_strict")
        return PipelineCheckpointProfile::RAW_STRICT;
    if (*text == "optimized_strict")
        return PipelineCheckpointProfile::OPTIMIZED_STRICT;
    if (*text == "optimized_relaxed")
        return PipelineCheckpointProfile::OPTIMIZED_RELAXED;
    return make_string_error(path + " has unknown checkpoint profile '" + *text + "'");
}

const char *lifted_bb_type_name(lifter::lifted_bb_t::Type type)
{
    switch (type)
    {
    case lifter::lifted_bb_t::Type::REAL:
        return "REAL";
    case lifter::lifted_bb_t::Type::SYNTHETIC:
        return "SYNTHETIC";
    }
    return "UNKNOWN";
}

llvm::Expected<lifter::lifted_bb_t::Type> parse_lifted_bb_type_value(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "REAL")
        return lifter::lifted_bb_t::Type::REAL;
    if (*text == "SYNTHETIC")
        return lifter::lifted_bb_t::Type::SYNTHETIC;
    return make_string_error(path + " has unknown lifted BB type '" + *text + "'");
}

const char *edge_type_name(lifter::edge_t::Type type)
{
    switch (type)
    {
    case lifter::edge_t::Type::CONTROL_FLOW:
        return "CONTROL_FLOW";
    case lifter::edge_t::Type::FALLTHROUGH:
        return "FALLTHROUGH";
    case lifter::edge_t::Type::SYNTHETIC_EXTERNAL:
        return "SYNTHETIC_EXTERNAL";
    case lifter::edge_t::Type::SYNTHETIC_RECURSIVE_CALL:
        return "SYNTHETIC_RECURSIVE_CALL";
    case lifter::edge_t::Type::SYNTHETIC_INDIRECT:
        return "SYNTHETIC_INDIRECT";
    case lifter::edge_t::Type::SYNTHETIC_RETURN:
        return "SYNTHETIC_RETURN";
    }
    return "UNKNOWN";
}

llvm::Expected<lifter::edge_t::Type> parse_edge_type_value(const llvm::json::Value &value,
                                                            const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "CONTROL_FLOW")
        return lifter::edge_t::Type::CONTROL_FLOW;
    if (*text == "FALLTHROUGH")
        return lifter::edge_t::Type::FALLTHROUGH;
    if (*text == "SYNTHETIC_EXTERNAL")
        return lifter::edge_t::Type::SYNTHETIC_EXTERNAL;
    if (*text == "SYNTHETIC_RECURSIVE_CALL")
        return lifter::edge_t::Type::SYNTHETIC_RECURSIVE_CALL;
    if (*text == "SYNTHETIC_INDIRECT")
        return lifter::edge_t::Type::SYNTHETIC_INDIRECT;
    if (*text == "SYNTHETIC_RETURN")
        return lifter::edge_t::Type::SYNTHETIC_RETURN;
    return make_string_error(path + " has unknown CFG edge type '" + *text + "'");
}

const char *synthetic_block_type_name(lifter::synthetic_block_info_t::Type type)
{
    switch (type)
    {
    case lifter::synthetic_block_info_t::Type::EXTERNAL:
        return "EXTERNAL";
    case lifter::synthetic_block_info_t::Type::RECURSIVE:
        return "RECURSIVE";
    case lifter::synthetic_block_info_t::Type::INDIRECT:
        return "INDIRECT";
    }
    return "UNKNOWN";
}

llvm::Expected<lifter::synthetic_block_info_t::Type> parse_synthetic_block_type_value(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto text = parse_string_value(value, path);
    if (!text)
        return text.takeError();
    if (*text == "EXTERNAL")
        return lifter::synthetic_block_info_t::Type::EXTERNAL;
    if (*text == "RECURSIVE")
        return lifter::synthetic_block_info_t::Type::RECURSIVE;
    if (*text == "INDIRECT")
        return lifter::synthetic_block_info_t::Type::INDIRECT;
    return make_string_error(path + " has unknown synthetic block type '" + *text + "'");
}


llvm::Expected<fault_injection::MutationCategory> parse_mutation_category_name(
    llvm::StringRef name,
    const std::string &path)
{
    using Category = fault_injection::MutationCategory;
    if (name == "ARITHMETIC")
        return Category::ARITHMETIC;
    if (name == "BITWISE")
        return Category::BITWISE;
    if (name == "COMPARISON_NEG")
        return Category::COMPARISON_NEG;
    if (name == "COMPARISON_BDRY")
        return Category::COMPARISON_BDRY;
    if (name == "OPERAND_SWAP")
        return Category::OPERAND_SWAP;
    if (name == "DROP_COMPUTATION")
        return Category::DROP_COMPUTATION;
    if (name == "CONSTANT_REPL")
        return Category::CONSTANT_REPL;
    if (name == "NEGATE_TRUNC")
        return Category::NEGATE_TRUNC;
    return make_string_error(path + " has unknown mutation category '" + name.str() + "'");
}

llvm::Expected<fault_injection::difficulty_t> parse_difficulty_name(llvm::StringRef name,
                                                                    const std::string &path)
{
    using Difficulty = fault_injection::difficulty_t;
    if (name == "EASY")
        return Difficulty::EASY;
    if (name == "MEDIUM")
        return Difficulty::MEDIUM;
    if (name == "HARD")
        return Difficulty::HARD;
    return make_string_error(path + " has unknown mutation difficulty '" + name.str() + "'");
}

llvm::json::Object count_pair_json(const std::pair<size_t, size_t> &counts)
{
    llvm::json::Object obj;
    obj["killed"] = static_cast<uint64_t>(counts.first);
    obj["total"] = static_cast<uint64_t>(counts.second);
    return obj;
}

llvm::Expected<std::pair<size_t, size_t>> parse_count_pair_json(const llvm::json::Value &value,
                                                                const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    auto killed_or = parse_required_field<size_t>(obj, "killed", path, parse_size_value);
    if (!killed_or)
        return killed_or.takeError();
    auto total_or = parse_required_field<size_t>(obj, "total", path, parse_size_value);
    if (!total_or)
        return total_or.takeError();
    return std::make_pair(*killed_or, *total_or);
}

llvm::json::Object exit_type_counts_json(const pipeline::ExitTypeCounts &counts)
{
    llvm::json::Object obj;
    for (const auto &[type, count] : counts)
        obj[exit_type_name(type)] = static_cast<uint64_t>(count);
    return obj;
}

llvm::Expected<pipeline::ExitTypeCounts> parse_exit_type_counts_json(const llvm::json::Value &value,
                                                                     const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    pipeline::ExitTypeCounts counts;
    for (const auto &entry : **obj_or)
    {
        auto type_or = parse_exit_type_name(entry.first, json_path(path, entry.first));
        if (!type_or)
            return type_or.takeError();
        auto count_or = parse_size_value(entry.second, json_path(path, entry.first));
        if (!count_or)
            return count_or.takeError();
        counts[*type_or] = *count_or;
    }
    return counts;
}

llvm::json::Object lift_stats_json(const lifter::lift_stats_t &stats)
{
    llvm::json::Object obj;
    obj["bbs_lifted"] = static_cast<uint64_t>(stats.bbs_lifted);
    obj["bbs_cached"] = static_cast<uint64_t>(stats.bbs_cached);
    obj["bbs_total"] = static_cast<uint64_t>(stats.bbs_total);
    obj["lift_time_ms"] = stats.lift_time_ms;
    obj["resolve_time_ms"] = stats.resolve_time_ms;
    obj["stitch_time_ms"] = stats.stitch_time_ms;
    obj["total_time_ms"] = stats.total_time_ms;
    return obj;
}

llvm::Expected<lifter::lift_stats_t> parse_lift_stats_json(const llvm::json::Value &value,
                                                            const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    lifter::lift_stats_t stats;
    auto bbs_lifted_or = parse_required_field<size_t>(obj, "bbs_lifted", path, parse_size_value);
    if (!bbs_lifted_or)
        return bbs_lifted_or.takeError();
    stats.bbs_lifted = *bbs_lifted_or;
    auto bbs_cached_or = parse_required_field<size_t>(obj, "bbs_cached", path, parse_size_value);
    if (!bbs_cached_or)
        return bbs_cached_or.takeError();
    stats.bbs_cached = *bbs_cached_or;
    auto bbs_total_or = parse_required_field<size_t>(obj, "bbs_total", path, parse_size_value);
    if (!bbs_total_or)
        return bbs_total_or.takeError();
    stats.bbs_total = *bbs_total_or;
    auto lift_ms_or = parse_required_field<double>(obj, "lift_time_ms", path, parse_double_value);
    if (!lift_ms_or)
        return lift_ms_or.takeError();
    stats.lift_time_ms = *lift_ms_or;
    auto resolve_ms_or = parse_required_field<double>(obj, "resolve_time_ms", path, parse_double_value);
    if (!resolve_ms_or)
        return resolve_ms_or.takeError();
    stats.resolve_time_ms = *resolve_ms_or;
    auto stitch_ms_or = parse_required_field<double>(obj, "stitch_time_ms", path, parse_double_value);
    if (!stitch_ms_or)
        return stitch_ms_or.takeError();
    stats.stitch_time_ms = *stitch_ms_or;
    auto total_ms_or = parse_required_field<double>(obj, "total_time_ms", path, parse_double_value);
    if (!total_ms_or)
        return total_ms_or.takeError();
    stats.total_time_ms = *total_ms_or;
    return stats;
}

llvm::json::Object edge_json(const lifter::edge_t &edge)
{
    llvm::json::Object obj;
    obj["source"] = static_cast<uint64_t>(edge.source);
    obj["dest"] = static_cast<uint64_t>(edge.dest);
    obj["type"] = edge_type_name(edge.type);
    return obj;
}

llvm::Expected<lifter::edge_t> parse_edge_json(const llvm::json::Value &value,
                                               const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    auto source_or = parse_required_field<uint64_t>(obj, "source", path, parse_uint_value);
    if (!source_or)
        return source_or.takeError();
    auto dest_or = parse_required_field<uint64_t>(obj, "dest", path, parse_uint_value);
    if (!dest_or)
        return dest_or.takeError();
    auto type_or = parse_required_field<lifter::edge_t::Type>(obj, "type", path, parse_edge_type_value);
    if (!type_or)
        return type_or.takeError();
    return lifter::edge_t(static_cast<lifter::bb_id_t>(*source_or),
                          static_cast<lifter::bb_id_t>(*dest_or),
                          *type_or);
}

llvm::json::Object lifted_bb_json(const lifter::lifted_bb_t &bb)
{
    llvm::json::Object obj;
    obj["type"] = lifted_bb_type_name(bb.type);
    obj["id"] = static_cast<uint64_t>(bb.id);
    obj["func_name"] = bb.func_name;
    if (bb.rva_range)
    {
        obj["rva_start"] = bb.rva_range->start();
        obj["rva_end"] = bb.rva_range->end();
    }
    if (bb.static_target_rva)
        obj["static_target_rva"] = *bb.static_target_rva;
    if (bb.static_continuation_rva)
        obj["static_continuation_rva"] = *bb.static_continuation_rva;
    return obj;
}

llvm::Expected<lifter::lifted_bb_t> parse_lifted_bb_json(const llvm::json::Value &value,
                                                          const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    lifter::lifted_bb_t bb{
        .type = lifter::lifted_bb_t::Type::REAL,
        .id = 0,
        .func_name = {},
        .rva_range = std::nullopt,
        .terminating_category = std::nullopt,
        .static_target_rva = std::nullopt,
        .static_continuation_rva = std::nullopt,
        .was_truncated_by_stop = false,
    };
    auto type_or = parse_required_field<lifter::lifted_bb_t::Type>(obj, "type", path, parse_lifted_bb_type_value);
    if (!type_or)
        return type_or.takeError();
    bb.type = *type_or;
    auto id_or = parse_required_field<uint64_t>(obj, "id", path, parse_uint_value);
    if (!id_or)
        return id_or.takeError();
    bb.id = static_cast<lifter::bb_id_t>(*id_or);
    auto func_name_or = parse_required_field<std::string>(obj, "func_name", path, parse_string_value);
    if (!func_name_or)
        return func_name_or.takeError();
    bb.func_name = std::move(*func_name_or);
    auto start_or = parse_optional_field<uint64_t>(obj, "rva_start", path, parse_uint_value);
    if (!start_or)
        return start_or.takeError();
    auto end_or = parse_optional_field<uint64_t>(obj, "rva_end", path, parse_uint_value);
    if (!end_or)
        return end_or.takeError();
    if (start_or->has_value() || end_or->has_value())
    {
        if (!start_or->has_value() || !end_or->has_value() || **end_or < **start_or)
            return make_string_error(path + ".rva_start/.rva_end must form a valid range");
        bb.rva_range = llvm::AddressRange(**start_or, **end_or);
    }
    auto target_or = parse_optional_field<uint64_t>(obj, "static_target_rva", path, parse_uint_value);
    if (!target_or)
        return target_or.takeError();
    bb.static_target_rva = std::move(*target_or);
    auto continuation_or = parse_optional_field<uint64_t>(obj, "static_continuation_rva", path, parse_uint_value);
    if (!continuation_or)
        return continuation_or.takeError();
    bb.static_continuation_rva = std::move(*continuation_or);
    return bb;
}

llvm::json::Object synthetic_block_json(const visualization::SyntheticBlockSnapshot &block)
{
    llvm::json::Object obj;
    obj["type"] = synthetic_block_type_name(block.type);
    obj["annotation_name"] = block.annotation_name;
    if (block.dest_addr)
        obj["dest_addr"] = *block.dest_addr;
    return obj;
}

llvm::Expected<visualization::SyntheticBlockSnapshot> parse_synthetic_block_json(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    visualization::SyntheticBlockSnapshot block{
        .type = lifter::synthetic_block_info_t::Type::EXTERNAL,
        .dest_addr = std::nullopt,
        .annotation_name = {},
    };
    auto type_or = parse_required_field<lifter::synthetic_block_info_t::Type>(obj, "type", path, parse_synthetic_block_type_value);
    if (!type_or)
        return type_or.takeError();
    block.type = *type_or;
    auto annotation_or = parse_required_field<std::string>(obj, "annotation_name", path, parse_string_value);
    if (!annotation_or)
        return annotation_or.takeError();
    block.annotation_name = std::move(*annotation_or);
    auto dest_or = parse_optional_field<uint64_t>(obj, "dest_addr", path, parse_uint_value);
    if (!dest_or)
        return dest_or.takeError();
    block.dest_addr = std::move(*dest_or);
    return block;
}

llvm::json::Object cfg_snapshot_json(const visualization::CfgSnapshot &cfg)
{
    llvm::json::Object obj;
    llvm::json::Array edges;
    for (const auto &edge : cfg.edges)
        edges.push_back(edge_json(edge));
    llvm::json::Array basic_blocks;
    for (const auto &bb : cfg.basic_blocks)
        basic_blocks.push_back(lifted_bb_json(bb));
    llvm::json::Object synthetic_blocks;
    for (const auto &[id, block] : cfg.synthetic_blocks)
        synthetic_blocks[std::to_string(id)] = synthetic_block_json(block);
    obj["edges"] = std::move(edges);
    obj["basic_blocks"] = std::move(basic_blocks);
    obj["synthetic_blocks"] = std::move(synthetic_blocks);
    obj["entry_rva"] = cfg.entry_rva;
    obj["func_name"] = cfg.func_name;
    return obj;
}

llvm::Expected<visualization::CfgSnapshot> parse_cfg_snapshot_json(const llvm::json::Value &value,
                                                                    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    visualization::CfgSnapshot cfg;
    auto edges_or = parse_required_field<const llvm::json::Array *>(obj, "edges", path, require_array);
    if (!edges_or)
        return edges_or.takeError();
    for (size_t index = 0; index < (*edges_or)->size(); ++index)
    {
        auto edge_or = parse_edge_json((**edges_or)[index], path + ".edges[" + std::to_string(index) + "]");
        if (!edge_or)
            return edge_or.takeError();
        cfg.edges.insert(std::move(*edge_or));
    }
    auto bbs_or = parse_required_field<const llvm::json::Array *>(obj, "basic_blocks", path, require_array);
    if (!bbs_or)
        return bbs_or.takeError();
    for (size_t index = 0; index < (*bbs_or)->size(); ++index)
    {
        auto bb_or = parse_lifted_bb_json((**bbs_or)[index], path + ".basic_blocks[" + std::to_string(index) + "]");
        if (!bb_or)
            return bb_or.takeError();
        cfg.basic_blocks.insert(std::move(*bb_or));
    }
    if (const llvm::json::Value *synthetic_value = obj.get("synthetic_blocks"))
    {
        auto synthetic_obj_or = require_object(*synthetic_value, path + ".synthetic_blocks");
        if (!synthetic_obj_or)
            return synthetic_obj_or.takeError();
        for (const auto &entry : **synthetic_obj_or)
        {
            auto id_or = parse_uint_key(entry.first, path + ".synthetic_blocks");
            if (!id_or)
                return id_or.takeError();
            auto block_or = parse_synthetic_block_json(entry.second,
                path + ".synthetic_blocks." + entry.first.str());
            if (!block_or)
                return block_or.takeError();
            cfg.synthetic_blocks[static_cast<lifter::bb_id_t>(*id_or)] = std::move(*block_or);
        }
    }
    auto entry_rva_or = parse_required_field<uint64_t>(obj, "entry_rva", path, parse_uint_value);
    if (!entry_rva_or)
        return entry_rva_or.takeError();
    cfg.entry_rva = *entry_rva_or;
    auto func_name_or = parse_required_field<std::string>(obj, "func_name", path, parse_string_value);
    if (!func_name_or)
        return func_name_or.takeError();
    cfg.func_name = std::move(*func_name_or);
    return cfg;
}

llvm::json::Object stage_report_json(const pipeline::StageReport &stage)
{
    llvm::json::Object obj;
    obj["stage_name"] = stage.stage_name;
    obj["total_runs"] = static_cast<uint64_t>(stage.total_runs);
    obj["pass_count"] = static_cast<uint64_t>(stage.pass_count);
    obj["fail_count"] = static_cast<uint64_t>(stage.fail_count);
    obj["incomparable"] = static_cast<uint64_t>(stage.incomparable);
    obj["reruns_triggered"] = static_cast<uint64_t>(stage.reruns_triggered);
    obj["rerun_resolved"] = static_cast<uint64_t>(stage.rerun_resolved);
    obj["corpus_added"] = static_cast<uint64_t>(stage.corpus_added);
    obj["cumulative_unique_blocks"] = static_cast<uint64_t>(stage.cumulative_unique_blocks);
    obj["src_exit_types"] = exit_type_counts_json(stage.src_exit_types);
    obj["src_initial_exit_types"] = exit_type_counts_json(stage.src_initial_exit_types);
    obj["tgt_exit_types"] = exit_type_counts_json(stage.tgt_exit_types);
    obj["src_wall_ns"] = static_cast<uint64_t>(stage.src_wall_ns.count());
    obj["tgt_wall_ns"] = static_cast<uint64_t>(stage.tgt_wall_ns.count());
    return obj;
}

llvm::Expected<pipeline::StageReport> parse_stage_report_json(const llvm::json::Value &value,
                                                              const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    pipeline::StageReport stage;
    auto stage_name_or = parse_required_field<std::string>(obj, "stage_name", path, parse_string_value);
    if (!stage_name_or)
        return stage_name_or.takeError();
    stage.stage_name = std::move(*stage_name_or);
    auto total_runs_or = parse_required_field<size_t>(obj, "total_runs", path, parse_size_value);
    if (!total_runs_or)
        return total_runs_or.takeError();
    stage.total_runs = *total_runs_or;
    auto pass_count_or = parse_required_field<size_t>(obj, "pass_count", path, parse_size_value);
    if (!pass_count_or)
        return pass_count_or.takeError();
    stage.pass_count = *pass_count_or;
    auto fail_count_or = parse_required_field<size_t>(obj, "fail_count", path, parse_size_value);
    if (!fail_count_or)
        return fail_count_or.takeError();
    stage.fail_count = *fail_count_or;
    auto incomparable_or = parse_required_field<size_t>(obj, "incomparable", path, parse_size_value);
    if (!incomparable_or)
        return incomparable_or.takeError();
    stage.incomparable = *incomparable_or;
    auto reruns_triggered_or = parse_required_field<size_t>(obj, "reruns_triggered", path, parse_size_value);
    if (!reruns_triggered_or)
        return reruns_triggered_or.takeError();
    stage.reruns_triggered = *reruns_triggered_or;
    auto rerun_resolved_or = parse_required_field<size_t>(obj, "rerun_resolved", path, parse_size_value);
    if (!rerun_resolved_or)
        return rerun_resolved_or.takeError();
    stage.rerun_resolved = *rerun_resolved_or;
    auto corpus_added_or = parse_required_field<size_t>(obj, "corpus_added", path, parse_size_value);
    if (!corpus_added_or)
        return corpus_added_or.takeError();
    stage.corpus_added = *corpus_added_or;
    auto cumulative_unique_blocks_or = parse_required_field<size_t>(obj, "cumulative_unique_blocks", path, parse_size_value);
    if (!cumulative_unique_blocks_or)
        return cumulative_unique_blocks_or.takeError();
    stage.cumulative_unique_blocks = *cumulative_unique_blocks_or;
    auto src_exit_types_or = parse_required_field<pipeline::ExitTypeCounts>(obj, "src_exit_types", path, parse_exit_type_counts_json);
    if (!src_exit_types_or)
        return src_exit_types_or.takeError();
    stage.src_exit_types = std::move(*src_exit_types_or);
    auto src_initial_exit_types_or = parse_required_field<pipeline::ExitTypeCounts>(obj, "src_initial_exit_types", path, parse_exit_type_counts_json);
    if (!src_initial_exit_types_or)
        return src_initial_exit_types_or.takeError();
    stage.src_initial_exit_types = std::move(*src_initial_exit_types_or);
    auto tgt_exit_types_or = parse_required_field<pipeline::ExitTypeCounts>(obj, "tgt_exit_types", path, parse_exit_type_counts_json);
    if (!tgt_exit_types_or)
        return tgt_exit_types_or.takeError();
    stage.tgt_exit_types = std::move(*tgt_exit_types_or);
    auto src_wall_ns_or = parse_required_field<uint64_t>(obj, "src_wall_ns", path, parse_uint_value);
    if (!src_wall_ns_or)
        return src_wall_ns_or.takeError();
    stage.src_wall_ns = std::chrono::nanoseconds(static_cast<int64_t>(*src_wall_ns_or));
    auto tgt_wall_ns_or = parse_required_field<uint64_t>(obj, "tgt_wall_ns", path, parse_uint_value);
    if (!tgt_wall_ns_or)
        return tgt_wall_ns_or.takeError();
    stage.tgt_wall_ns = std::chrono::nanoseconds(static_cast<int64_t>(*tgt_wall_ns_or));
    return stage;
}

pipeline::Corpus make_placeholder_corpus(size_t entries,
                                          size_t unique_blocks,
                                          const std::unordered_map<uint64_t, uint64_t> &src_block_hits)
{
    pipeline::Corpus corpus;
    auto classifier = pipeline::make_natural_exit_classifier();
    if (entries == 0)
        return corpus;

    std::vector<uint64_t> seed_trace;
    seed_trace.reserve(unique_blocks);
    for (const auto &[rva, _] : src_block_hits)
    {
        if (seed_trace.size() == unique_blocks)
            break;
        seed_trace.push_back(rva);
    }
    for (uint64_t next = 0; seed_trace.size() < unique_blocks; ++next)
        seed_trace.push_back(0xF000'0000'0000'0000ULL + next);

    for (size_t index = 0; index < entries; ++index)
    {
        pipeline::CorpusEntry entry{};
        entry.exit_reason = verification::exit_type::NATURAL_EXIT;
        entry.run_index = static_cast<uint64_t>(index);
        if (index == 0)
            entry.bb_trace = seed_trace;
        corpus.add_if_interesting(std::move(entry), classifier);
    }
    return corpus;
}

llvm::json::Object block_hits_json(const std::unordered_map<uint64_t, uint64_t> &hits)
{
    llvm::json::Object obj;
    for (const auto &[rva, count] : hits)
        obj[std::to_string(rva)] = count;
    return obj;
}

llvm::Expected<std::unordered_map<uint64_t, uint64_t>> parse_block_hits_json(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    std::unordered_map<uint64_t, uint64_t> hits;
    for (const auto &entry : **obj_or)
    {
        auto rva_or = parse_uint_key(entry.first, path);
        if (!rva_or)
            return rva_or.takeError();
        auto count_or = parse_uint_value(entry.second, json_path(path, entry.first));
        if (!count_or)
            return count_or.takeError();
        hits[*rva_or] = *count_or;
    }
    return hits;
}

llvm::json::Object pipeline_report_json(const pipeline::PipelineReport &report)
{
    llvm::json::Object obj;
    llvm::json::Array stages;
    for (const auto &stage : report.stages)
        stages.push_back(stage_report_json(stage));
    llvm::json::Object final_corpus;
    final_corpus["entries"] = static_cast<uint64_t>(report.final_corpus.size());
    final_corpus["unique_blocks"] = static_cast<uint64_t>(report.final_corpus.unique_blocks_covered());
    obj["pipeline_name"] = report.pipeline_name;
    obj["stages"] = std::move(stages);
    obj["final_corpus"] = std::move(final_corpus);
    obj["src_block_hits"] = block_hits_json(report.src_block_hits);
    return obj;
}

llvm::Expected<pipeline::PipelineReport> parse_pipeline_report_json(const llvm::json::Value &value,
                                                                    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    pipeline::PipelineReport report;
    auto pipeline_name_or = parse_required_field<std::string>(obj, "pipeline_name", path, parse_string_value);
    if (!pipeline_name_or)
        return pipeline_name_or.takeError();
    report.pipeline_name = std::move(*pipeline_name_or);
    auto stages_or = parse_required_field<const llvm::json::Array *>(obj, "stages", path, require_array);
    if (!stages_or)
        return stages_or.takeError();
    for (size_t index = 0; index < (*stages_or)->size(); ++index)
    {
        auto stage_or = parse_stage_report_json((**stages_or)[index], path + ".stages[" + std::to_string(index) + "]");
        if (!stage_or)
            return stage_or.takeError();
        report.stages.push_back(std::move(*stage_or));
    }
    if (const llvm::json::Value *hits_value = obj.get("src_block_hits"))
    {
        auto hits_or = parse_block_hits_json(*hits_value, path + ".src_block_hits");
        if (!hits_or)
            return hits_or.takeError();
        report.src_block_hits = std::move(*hits_or);
    }
    size_t final_corpus_entries = 0;
    size_t final_corpus_unique_blocks = report.src_block_hits.size();
    if (const llvm::json::Value *corpus_value = obj.get("final_corpus"))
    {
        auto corpus_obj_or = require_object(*corpus_value, path + ".final_corpus");
        if (!corpus_obj_or)
            return corpus_obj_or.takeError();
        const auto &corpus_obj = **corpus_obj_or;
        auto entries_or = parse_required_field<size_t>(corpus_obj, "entries", path + ".final_corpus", parse_size_value);
        if (!entries_or)
            return entries_or.takeError();
        final_corpus_entries = *entries_or;
        auto unique_blocks_or = parse_required_field<size_t>(corpus_obj, "unique_blocks", path + ".final_corpus", parse_size_value);
        if (!unique_blocks_or)
            return unique_blocks_or.takeError();
        final_corpus_unique_blocks = *unique_blocks_or;
    }
    report.final_corpus = make_placeholder_corpus(
        final_corpus_entries, final_corpus_unique_blocks, report.src_block_hits);
    return report;
}

llvm::json::Object verification_phase_json(const VerificationPhaseResult &phase)
{
    llvm::json::Object obj;
    obj["status"] = phase_status_name(phase.status);
    obj["error"] = phase.error;
    obj["skip_reason"] = phase.skip_reason;
    if (phase.report)
        obj["report"] = pipeline_report_json(*phase.report);
    return obj;
}

llvm::Expected<VerificationPhaseResult> parse_verification_phase_json(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    VerificationPhaseResult phase;
    auto status_or = parse_required_field<PhaseStatus>(obj, "status", path, parse_phase_status_value);
    if (!status_or)
        return status_or.takeError();
    phase.status = *status_or;
    if (const auto *error_value = obj.get("error"))
    {
        auto error_or = parse_string_value(*error_value, path + ".error");
        if (!error_or)
            return error_or.takeError();
        phase.error = std::move(*error_or);
    }
    if (const auto *reason_value = obj.get("skip_reason"))
    {
        auto reason_or = parse_string_value(*reason_value, path + ".skip_reason");
        if (!reason_or)
            return reason_or.takeError();
        phase.skip_reason = std::move(*reason_or);
    }
    auto report_or = parse_optional_field<pipeline::PipelineReport>(obj, "report", path, parse_pipeline_report_json);
    if (!report_or)
        return report_or.takeError();
    phase.report = std::move(*report_or);
    return phase;
}

llvm::json::Object mutation_category_counts_json(
    const std::map<fault_injection::MutationCategory, std::pair<size_t, size_t>> &counts)
{
    llvm::json::Object obj;
    for (const auto &[category, count] : counts)
        obj[std::string(fault_injection::category_name(category))] = count_pair_json(count);
    return obj;
}

llvm::Expected<std::map<fault_injection::MutationCategory, std::pair<size_t, size_t>>>
parse_mutation_category_counts_json(const llvm::json::Value &value,
                                    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    std::map<fault_injection::MutationCategory, std::pair<size_t, size_t>> counts;
    for (const auto &entry : **obj_or)
    {
        auto category_or = parse_mutation_category_name(entry.first, json_path(path, entry.first));
        if (!category_or)
            return category_or.takeError();
        auto count_or = parse_count_pair_json(entry.second, json_path(path, entry.first));
        if (!count_or)
            return count_or.takeError();
        counts[*category_or] = std::move(*count_or);
    }
    return counts;
}

llvm::json::Object difficulty_counts_json(
    const std::map<fault_injection::difficulty_t, std::pair<size_t, size_t>> &counts)
{
    llvm::json::Object obj;
    for (const auto &[difficulty, count] : counts)
        obj[std::string(fault_injection::difficulty_name(difficulty))] = count_pair_json(count);
    return obj;
}

llvm::Expected<std::map<fault_injection::difficulty_t, std::pair<size_t, size_t>>>
parse_difficulty_counts_json(const llvm::json::Value &value, const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    std::map<fault_injection::difficulty_t, std::pair<size_t, size_t>> counts;
    for (const auto &entry : **obj_or)
    {
        auto difficulty_or = parse_difficulty_name(entry.first, json_path(path, entry.first));
        if (!difficulty_or)
            return difficulty_or.takeError();
        auto count_or = parse_count_pair_json(entry.second, json_path(path, entry.first));
        if (!count_or)
            return count_or.takeError();
        counts[*difficulty_or] = std::move(*count_or);
    }
    return counts;
}

llvm::json::Object width_counts_json(const std::map<unsigned, std::pair<size_t, size_t>> &counts)
{
    llvm::json::Object obj;
    for (const auto &[width_bits, count] : counts)
        obj[std::to_string(width_bits)] = count_pair_json(count);
    return obj;
}

llvm::Expected<std::map<unsigned, std::pair<size_t, size_t>>> parse_width_counts_json(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    std::map<unsigned, std::pair<size_t, size_t>> counts;
    for (const auto &entry : **obj_or)
    {
        auto width_or = parse_uint_key(entry.first, json_path(path, entry.first));
        if (!width_or)
            return width_or.takeError();
        auto count_or = parse_count_pair_json(entry.second, json_path(path, entry.first));
        if (!count_or)
            return count_or.takeError();
        counts[static_cast<unsigned>(*width_or)] = std::move(*count_or);
    }
    return counts;
}

llvm::json::Object mutation_report_json(const fault_injection::MutationReport &report)
{
    llvm::json::Object obj;
    obj["func_name"] = report.func_name;
    obj["binary_stem"] = report.binary_stem;
    obj["total_enumerated"] = static_cast<uint64_t>(report.total_enumerated);
    obj["total_mutants"] = static_cast<uint64_t>(report.total_mutants);
    obj["budget_requested"] = static_cast<uint64_t>(report.budget_requested);
    obj["killed"] = static_cast<uint64_t>(report.killed);
    obj["survived"] = static_cast<uint64_t>(report.survived);
    obj["equivalent"] = static_cast<uint64_t>(report.equivalent);
    obj["errors"] = static_cast<uint64_t>(report.errors);
    obj["lift_duration_ms"] = report.lift_duration_ms;
    obj["campaign_duration_ms"] = report.campaign_duration_ms;
    obj["by_category"] = mutation_category_counts_json(report.by_category);
    obj["by_difficulty"] = difficulty_counts_json(report.by_difficulty);
    obj["by_width_bits"] = width_counts_json(report.by_width_bits);
    return obj;
}

llvm::Expected<fault_injection::MutationReport> parse_mutation_report_json(
    const llvm::json::Value &value,
    const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    fault_injection::MutationReport report;
    auto func_name_or = parse_required_field<std::string>(obj, "func_name", path, parse_string_value);
    if (!func_name_or)
        return func_name_or.takeError();
    report.func_name = std::move(*func_name_or);
    auto binary_stem_or = parse_required_field<std::string>(obj, "binary_stem", path, parse_string_value);
    if (!binary_stem_or)
        return binary_stem_or.takeError();
    report.binary_stem = std::move(*binary_stem_or);
    auto total_enumerated_or = parse_required_field<size_t>(obj, "total_enumerated", path, parse_size_value);
    if (!total_enumerated_or)
        return total_enumerated_or.takeError();
    report.total_enumerated = *total_enumerated_or;
    auto total_mutants_or = parse_required_field<size_t>(obj, "total_mutants", path, parse_size_value);
    if (!total_mutants_or)
        return total_mutants_or.takeError();
    report.total_mutants = *total_mutants_or;
    auto budget_or = parse_required_field<size_t>(obj, "budget_requested", path, parse_size_value);
    if (!budget_or)
        return budget_or.takeError();
    report.budget_requested = *budget_or;
    auto killed_or = parse_required_field<size_t>(obj, "killed", path, parse_size_value);
    if (!killed_or)
        return killed_or.takeError();
    report.killed = *killed_or;
    auto survived_or = parse_required_field<size_t>(obj, "survived", path, parse_size_value);
    if (!survived_or)
        return survived_or.takeError();
    report.survived = *survived_or;
    auto equivalent_or = parse_required_field<size_t>(obj, "equivalent", path, parse_size_value);
    if (!equivalent_or)
        return equivalent_or.takeError();
    report.equivalent = *equivalent_or;
    auto errors_or = parse_required_field<size_t>(obj, "errors", path, parse_size_value);
    if (!errors_or)
        return errors_or.takeError();
    report.errors = *errors_or;
    auto lift_ms_or = parse_required_field<double>(obj, "lift_duration_ms", path, parse_double_value);
    if (!lift_ms_or)
        return lift_ms_or.takeError();
    report.lift_duration_ms = *lift_ms_or;
    auto campaign_ms_or = parse_required_field<double>(obj, "campaign_duration_ms", path, parse_double_value);
    if (!campaign_ms_or)
        return campaign_ms_or.takeError();
    report.campaign_duration_ms = *campaign_ms_or;
    if (const llvm::json::Value *categories_value = obj.get("by_category"))
    {
        auto categories_or = parse_mutation_category_counts_json(*categories_value, path + ".by_category");
        if (!categories_or)
            return categories_or.takeError();
        report.by_category = std::move(*categories_or);
    }
    if (const llvm::json::Value *difficulty_value = obj.get("by_difficulty"))
    {
        auto difficulty_or = parse_difficulty_counts_json(*difficulty_value, path + ".by_difficulty");
        if (!difficulty_or)
            return difficulty_or.takeError();
        report.by_difficulty = std::move(*difficulty_or);
    }
    if (const llvm::json::Value *width_value = obj.get("by_width_bits"))
    {
        auto width_or = parse_width_counts_json(*width_value, path + ".by_width_bits");
        if (!width_or)
            return width_or.takeError();
        report.by_width_bits = std::move(*width_or);
    }
    return report;
}

llvm::json::Object mutation_phase_json(const MutationPhaseResult &phase)
{
    llvm::json::Object obj;
    obj["status"] = mutation_phase_status_name(phase.status);
    obj["error"] = phase.error;
    obj["skip_reason"] = phase.skip_reason;
    if (phase.report)
        obj["report"] = mutation_report_json(*phase.report);
    return obj;
}

llvm::Expected<MutationPhaseResult> parse_mutation_phase_json(const llvm::json::Value &value,
                                                              const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    MutationPhaseResult phase;
    auto status_or = parse_required_field<MutationPhaseStatus>(obj, "status", path, parse_mutation_phase_status_value);
    if (!status_or)
        return status_or.takeError();
    phase.status = *status_or;
    if (const auto *error_value = obj.get("error"))
    {
        auto error_or = parse_string_value(*error_value, path + ".error");
        if (!error_or)
            return error_or.takeError();
        phase.error = std::move(*error_or);
    }
    if (const auto *reason_value = obj.get("skip_reason"))
    {
        auto reason_or = parse_string_value(*reason_value, path + ".skip_reason");
        if (!reason_or)
            return reason_or.takeError();
        phase.skip_reason = std::move(*reason_or);
    }
    auto report_or = parse_optional_field<fault_injection::MutationReport>(obj, "report", path, parse_mutation_report_json);
    if (!report_or)
        return report_or.takeError();
    phase.report = std::move(*report_or);
    return phase;
}

llvm::json::Object eg3_profile_json(const Eg3ProfileResult &profile)
{
    llvm::json::Object obj;
    obj["profile"] = pipeline_checkpoint_profile_name(profile.profile);
    obj["selftest"] = verification_phase_json(profile.selftest);
    obj["mutation"] = mutation_phase_json(profile.mutation);
    return obj;
}

llvm::Expected<Eg3ProfileResult> parse_eg3_profile_json(const llvm::json::Value &value,
                                                         const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    auto profile_or = parse_required_field<PipelineCheckpointProfile>(obj, "profile", path, parse_checkpoint_profile_value);
    if (!profile_or)
        return profile_or.takeError();
    Eg3ProfileResult profile(*profile_or);
    auto selftest_or = parse_required_field<VerificationPhaseResult>(obj, "selftest", path, parse_verification_phase_json);
    if (!selftest_or)
        return selftest_or.takeError();
    profile.selftest = std::move(*selftest_or);
    auto mutation_or = parse_required_field<MutationPhaseResult>(obj, "mutation", path, parse_mutation_phase_json);
    if (!mutation_or)
        return mutation_or.takeError();
    profile.mutation = std::move(*mutation_or);
    return profile;
}

llvm::json::Object evaluation_record_json(const EvaluationRecord &record)
{
    llvm::json::Object obj;
    obj["lift_status"] = lift_status_name(record.lift_status);
    obj["lift_message"] = record.lift_message;
    if (record.lift_stats)
        obj["lift_stats"] = lift_stats_json(*record.lift_stats);
    if (record.cfg)
        obj["cfg"] = cfg_snapshot_json(*record.cfg);
    obj["raw_vs_native"] = verification_phase_json(record.raw_vs_native);
    obj["opt_vs_raw"] = verification_phase_json(record.opt_vs_raw);
    obj["eg3_strict"] = eg3_profile_json(record.eg3_strict);
    obj["eg3_relaxed"] = eg3_profile_json(record.eg3_relaxed);
    return obj;
}

llvm::Expected<EvaluationRecord> parse_evaluation_record_json(const llvm::json::Value &value,
                                                              const std::string &path)
{
    auto obj_or = require_object(value, path);
    if (!obj_or)
        return obj_or.takeError();
    const auto &obj = **obj_or;
    EvaluationRecord record;
    if (const llvm::json::Value *status_value = obj.get("lift_status"))
    {
        auto status_or = parse_lift_status_value(*status_value, path + ".lift_status");
        if (!status_or)
            return status_or.takeError();
        record.lift_status = *status_or;
    }
    if (const llvm::json::Value *message_value = obj.get("lift_message"))
    {
        auto message_or = parse_string_value(*message_value, path + ".lift_message");
        if (!message_or)
            return message_or.takeError();
        record.lift_message = std::move(*message_or);
    }
    auto lift_stats_or = parse_optional_field<lifter::lift_stats_t>(obj, "lift_stats", path, parse_lift_stats_json);
    if (!lift_stats_or)
        return lift_stats_or.takeError();
    record.lift_stats = std::move(*lift_stats_or);
    auto cfg_or = parse_optional_field<visualization::CfgSnapshot>(obj, "cfg", path, parse_cfg_snapshot_json);
    if (!cfg_or)
        return cfg_or.takeError();
    record.cfg = std::move(*cfg_or);
    if (const llvm::json::Value *raw_value = obj.get("raw_vs_native"))
    {
        auto raw_or = parse_verification_phase_json(*raw_value, path + ".raw_vs_native");
        if (!raw_or)
            return raw_or.takeError();
        record.raw_vs_native = std::move(*raw_or);
    }
    if (const llvm::json::Value *opt_value = obj.get("opt_vs_raw"))
    {
        auto opt_or = parse_verification_phase_json(*opt_value, path + ".opt_vs_raw");
        if (!opt_or)
            return opt_or.takeError();
        record.opt_vs_raw = std::move(*opt_or);
    }
    if (const llvm::json::Value *strict_value = obj.get("eg3_strict"))
    {
        auto strict_or = parse_eg3_profile_json(*strict_value, path + ".eg3_strict");
        if (!strict_or)
            return strict_or.takeError();
        record.eg3_strict = std::move(*strict_or);
    }
    if (const llvm::json::Value *relaxed_value = obj.get("eg3_relaxed"))
    {
        auto relaxed_or = parse_eg3_profile_json(*relaxed_value, path + ".eg3_relaxed");
        if (!relaxed_or)
            return relaxed_or.takeError();
        record.eg3_relaxed = std::move(*relaxed_or);
    }
    return record;
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

    std::unique_ptr<LIEF::Binary> binary = parse_binary_serialized(path);
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
                                  std::string_view phase_label,
                                  const std::string &func_name,
                                  std::shared_ptr<Executor> src,
                                  std::shared_ptr<Executor> tgt,
                                  PipelineCheckpointProfile profile,
                                  size_t deep_dive_count)
{
    VerificationPhaseResult phase;
    pipeline::Pipeline pl(make_default_pipeline(
        phase_label, func_name, std::move(src), std::move(tgt), profile));

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
                      const std::string &phase_label,
                      const std::string &lifted_function_name,
                      const llvm::Module &optimized_module,
                      const fault_injection::MutationCampaignConfig &cfg,
                      PipelineCheckpointProfile profile,
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
    report.func_name = phase_label;
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
        auto phase = run_phase(bin_ctx, entry_rva, phase_label,
                               phase_label, baseline_jit, mutant_jit,
                               profile,
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

void run_eg3_profile(BinaryContext &bin_ctx,
                     std::string_view phase_label,
                     const std::filesystem::path &binary_path,
                     uint64_t entry_rva,
                     const std::string &report_func_name,
                     const std::string &lifted_function_name,
                     const llvm::Module &optimized_module,
                     const fault_injection::MutationCampaignConfig &mutation_cfg,
                     double lift_duration_ms,
                     size_t deep_dive_count,
                     bool run_mutation,
                     Eg3ProfileResult &result)
{
    auto opt_self_src_or = make_opt_jit(optimized_module, lifted_function_name);
    if (!opt_self_src_or)
    {
        result.selftest.status = PhaseStatus::ERROR;
        result.selftest.error = llvm::toString(opt_self_src_or.takeError());
        mark_skipped(result.mutation, "o2 self-test setup failed");
        return;
    }

    auto opt_self_tgt_or = make_opt_jit(optimized_module, lifted_function_name);
    if (!opt_self_tgt_or)
    {
        result.selftest.status = PhaseStatus::ERROR;
        result.selftest.error = llvm::toString(opt_self_tgt_or.takeError());
        mark_skipped(result.mutation, "o2 self-test setup failed");
        return;
    }

    result.selftest = run_phase(
        bin_ctx, entry_rva, std::string(phase_label) + " self-test",
        report_func_name, *opt_self_src_or, *opt_self_tgt_or,
        result.profile, deep_dive_count);
    if (!run_mutation)
    {
        mark_skipped(result.mutation, "disabled");
        return;
    }

    if (!result.selftest.passed())
    {
        mark_skipped(result.mutation, "o2 self-test did not pass");
        return;
    }

    auto mutation_or = run_mutation_campaign(
        bin_ctx, binary_path, entry_rva, std::string(phase_label) + " mutation",
        lifted_function_name, optimized_module, mutation_cfg, result.profile, lift_duration_ms);
    if (!mutation_or)
    {
        result.mutation.status = MutationPhaseStatus::ERROR;
        result.mutation.error = llvm::toString(mutation_or.takeError());
        return;
    }

    result.mutation.status = MutationPhaseStatus::RUN;
    result.mutation.report = std::move(*mutation_or);
}
} // namespace

bool LiftAndVerifyResult::lift_succeeded() const
{
    return lift_status == LiftStatus::PASS;
}

bool FullPipelineResult::lift_succeeded() const
{
    return lift_status == LiftStatus::PASS;
}

bool FullPipelineResult::raw_pass() const
{
    return lift_succeeded() && raw_vs_native && raw_vs_native->total_failures() == 0;
}

bool FullPipelineResult::opt_pass() const
{
    if (!lift_succeeded() || !opt_transform_error.empty())
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

bool EvaluationRecord::lift_succeeded() const
{
    return lift_status == LiftStatus::PASS;
}

size_t EvaluationRecord::bbs_total() const
{
    return lift_succeeded() && lift_stats ? lift_stats->bbs_total : 0;
}

const char *lift_status_name(LiftStatus status)
{
    switch (status)
    {
    case LiftStatus::PASS:
        return "PASS";
    case LiftStatus::ERROR:
        return "ERROR";
    case LiftStatus::TIMEOUT:
        return "TIMEOUT";
    }
    return "UNKNOWN";
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

const char *pipeline_checkpoint_profile_name(PipelineCheckpointProfile profile)
{
    switch (profile)
    {
    case PipelineCheckpointProfile::RAW_STRICT:
        return "raw_strict";
    case PipelineCheckpointProfile::OPTIMIZED_STRICT:
        return "optimized_strict";
    case PipelineCheckpointProfile::OPTIMIZED_RELAXED:
        return "optimized_relaxed";
    }
    return "unknown";
}

pipeline::PipelineSpec make_default_pipeline(
    std::string_view phase_label,
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
        case PipelineCheckpointProfile::OPTIMIZED_STRICT:
            // Optimized-vs-optimized strict mode keeps structural BB/ext-call checks
            // without requiring exact write sequencing across equivalent O2 rewrites.
            cfg.sync_on = EF::BB | EF::EXT_CALL;
            cfg.compare_dims =
                DF::REG_STATE | DF::MEM_CONTENTS | DF::BB_TRACE | DF::EXT_CALLS;
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
    spec.name = std::string(phase_label) + "[" + func_name + "]";
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
        r.lift_status = LiftStatus::ERROR;
        r.lift_message = llvm::toString(artifacts_or.takeError());
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

    pipeline::Pipeline pl(make_default_pipeline("EG1 raw/native", func_name, *jit_or, *uc_or));
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
        r.lift_status = LiftStatus::ERROR;
        r.lift_message = llvm::toString(artifacts_or.takeError());
        return r;
    }

    auto artifacts = std::move(*artifacts_or);
    auto raw_jit_or = make_raw_jit(artifacts);
    if (!raw_jit_or)
        return raw_jit_or.takeError();
    auto uc_or = make_unicorn(artifacts, entry_rva);
    if (!uc_or)
        return uc_or.takeError();

    pipeline::Pipeline p1(make_default_pipeline("EG1 raw/native", func_name, *raw_jit_or, *uc_or));
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
        "EG2 raw/o2", func_name, *raw_jit_or, *opt_jit_or, PipelineCheckpointProfile::OPTIMIZED_RELAXED));
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
                     const EvaluationConfig &config,
                     LiftCompleteCallback on_lift_complete)
{
    EvaluationRecord result = make_base_record(config);

    auto artifacts_or = lift_artifacts(context, path, func_name, entry_rva, config.obfuscator);
    if (!artifacts_or)
        return make_lift_status_record(
            config, LiftStatus::ERROR, llvm::toString(artifacts_or.takeError()));

    auto artifacts = std::move(*artifacts_or);
    result.lift_stats = artifacts.lift_stats;
    result.cfg = artifacts.cfg;

    if (on_lift_complete)
    {
        if (auto err = on_lift_complete(result))
            return err;
    }

    std::shared_ptr<Executor> raw_jit;
    if (needs_raw_phase(config))
    {
        auto raw_jit_or = make_raw_jit(artifacts);
        if (!raw_jit_or)
        {
            result.raw_vs_native.status = PhaseStatus::ERROR;
            result.raw_vs_native.error = llvm::toString(raw_jit_or.takeError());
            if (needs_opt_phase(config))
                mark_skipped(result.opt_vs_raw, "raw JIT setup failed");
            skip_requested_eg3(result, config, "raw JIT setup failed");
            return result;
        }
        raw_jit = *raw_jit_or;

        auto uc_or = make_unicorn(artifacts, entry_rva);
        if (!uc_or)
        {
            result.raw_vs_native.status = PhaseStatus::ERROR;
            result.raw_vs_native.error = llvm::toString(uc_or.takeError());
            if (needs_opt_phase(config))
                mark_skipped(result.opt_vs_raw, "native executor setup failed");
            skip_requested_eg3(result, config, "native executor setup failed");
            return result;
        }

        result.raw_vs_native = run_phase(
            *artifacts.bin_ctx, entry_rva, "EG1 raw/native", func_name, raw_jit, *uc_or,
            config.raw_vs_native_profile, config.deep_dive_count);
    }
    else
    {
        mark_skipped(result.raw_vs_native, "disabled");
    }

    if (!needs_opt_phase(config))
    {
        mark_skipped(result.opt_vs_raw, "disabled");
        return result;
    }

    if (!result.raw_vs_native.passed())
    {
        mark_skipped(result.opt_vs_raw, "raw/native did not pass");
        skip_requested_eg3(result, config, "raw/native did not pass");
        return result;
    }

    auto opt_module = build_optimized_module(artifacts);
    auto opt_jit_or = make_opt_jit(*opt_module, artifacts.lifted_function_name);
    if (!opt_jit_or)
    {
        result.opt_vs_raw.status = PhaseStatus::ERROR;
        result.opt_vs_raw.error = llvm::toString(opt_jit_or.takeError());
        skip_requested_eg3(result, config, "optimized artifact setup failed");
        return result;
    }

    result.opt_vs_raw = run_phase(
        *artifacts.bin_ctx, entry_rva, "EG2 raw/o2", func_name, raw_jit, *opt_jit_or,
        config.opt_vs_raw_profile, config.deep_dive_count);

    if (!config.run_eg3_strict && !config.run_eg3_relaxed)
        return result;

    if (!result.opt_vs_raw.passed())
    {
        skip_requested_eg3(result, config, "o2/raw did not pass");
        return result;
    }

    const double lift_duration_ms = result.lift_stats ? result.lift_stats->total_time_ms : 0.0;
    if (config.run_eg3_strict)
    {
        run_eg3_profile(
            *artifacts.bin_ctx, "EG3 strict", path, entry_rva, func_name, artifacts.lifted_function_name,
            *opt_module, config.mutation_config, lift_duration_ms,
            config.deep_dive_count, config.run_mutation, result.eg3_strict);
    }

    if (config.run_eg3_relaxed)
    {
        run_eg3_profile(
            *artifacts.bin_ctx, "EG3 relaxed", path, entry_rva, func_name, artifacts.lifted_function_name,
            *opt_module, config.mutation_config, lift_duration_ms,
            config.deep_dive_count, config.run_mutation, result.eg3_relaxed);
    }

    return result;
}



EvaluationRecord make_lift_status_record(const EvaluationConfig &config,
                                         LiftStatus status,
                                         std::string message)
{
    EvaluationRecord result = make_base_record(config);
    result.lift_status = status;
    result.lift_message = status == LiftStatus::PASS ? std::string{} : std::move(message);

    if (status == LiftStatus::PASS)
        return result;

    const char *reason = lift_skip_reason(status);
    if (needs_raw_phase(config))
        mark_skipped(result.raw_vs_native, reason);
    if (needs_opt_phase(config))
        mark_skipped(result.opt_vs_raw, reason);
    skip_requested_eg3(result, config, reason);
    return result;
}

llvm::Error write_evaluation_record_json(const EvaluationRecord &record,
                                         const std::filesystem::path &path)
{
    std::error_code ec;
    if (!path.parent_path().empty())
    {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec)
            return make_string_error(
                "failed to create directory for '" + path.string() + "': " + ec.message());
    }

    llvm::raw_fd_ostream os(path.string(), ec, llvm::sys::fs::OF_Text);
    if (ec)
        return make_string_error(
            "failed to open '" + path.string() + "' for writing: " + ec.message());

    os << llvm::json::Value(evaluation_record_json(record));
    return llvm::Error::success();
}

llvm::Expected<EvaluationRecord> read_evaluation_record_json(const std::filesystem::path &path)
{
    auto buffer_or = llvm::MemoryBuffer::getFile(path.string());
    if (!buffer_or)
        return make_string_error(
            "failed to read '" + path.string() + "': " + buffer_or.getError().message());

    auto parsed_or = llvm::json::parse(buffer_or.get()->getBuffer());
    if (!parsed_or)
        return parsed_or.takeError();

    return parse_evaluation_record_json(*parsed_or, "evaluation_record");
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
