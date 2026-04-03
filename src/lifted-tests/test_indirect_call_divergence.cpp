#include "test_framework.hpp"

#include "eval_pipeline.hpp"
#include "compat/lief_compat.hpp"

#include <llvm/Support/Error.h>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>

#ifndef EVAL_INDIRECT_CALL_SO
#  error "EVAL_INDIRECT_CALL_SO must be defined at compile time (path to libeval-indirect-call.so)"
#endif

namespace
{
std::optional<uint64_t> find_export_va(LIEF::Binary &binary,
                                       const std::string &sym_name)
{
    auto r = binary.get_function_address(sym_name);
    if (!r)
        return std::nullopt;
    return *r;
}

template <typename T>
T unwrapExpected(llvm::Expected<T> value)
{
    CHECK(static_cast<bool>(value));
    if (!value)
    {
        llvm::consumeError(value.takeError());
        return T{};
    }
    return *value;
}

size_t total_passes(const lifted::pipeline::PipelineReport &report)
{
    size_t total = 0;
    for (const auto &stage : report.stages)
        total += stage.pass_count;
    return total;
}

size_t total_incomparables(const lifted::pipeline::PipelineReport &report)
{
    size_t total = 0;
    for (const auto &stage : report.stages)
        total += stage.incomparable;
    return total;
}

size_t count_tgt_exit(const lifted::pipeline::PipelineReport &report,
                      lifted::verification::exit_type reason)
{
    size_t total = 0;
    for (const auto &stage : report.stages)
    {
        auto it = stage.tgt_exit_types.find(reason);
        if (it != stage.tgt_exit_types.end())
            total += it->second;
    }
    return total;
}
} // namespace

TEST(indirect_call_invalid_targets_never_pass)
{
    const std::filesystem::path so_path = EVAL_INDIRECT_CALL_SO;

    auto binary = LIEF::Parser::parse(so_path);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    auto entry_va = find_export_va(*binary, "test");
    CHECK(entry_va.has_value());
    if (!entry_va)
        return;

    llvm::LLVMContext context;
    auto result = unwrapExpected(
        lifted::eval::lift_and_verify_named(context, so_path, "test", *entry_va, 0));

    CHECK_EQ(result.lift_status, lifted::eval::LiftStatus::PASS);
    CHECK(result.report.has_value());
    if (!result.report)
        return;

    const auto &report = *result.report;
    CHECK_EQ(total_passes(report), static_cast<size_t>(0));
    CHECK_EQ(total_incomparables(report), static_cast<size_t>(0));
    CHECK_EQ(report.total_failures(), report.total_runs());
    CHECK_EQ(count_tgt_exit(report, lifted::verification::exit_type::MISSING_BLOCK),
             report.total_runs());
}
