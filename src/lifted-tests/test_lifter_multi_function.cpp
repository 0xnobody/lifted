#include "test_framework.hpp"

#include "compat/lief_compat.hpp" // must be first: saves+undefines DEBUG before any glog header

#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
#include "abi/function_state_attrs.hpp"
#include "abi/systemv_x64.hpp"
#include "binary_context.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <optional>
#include <set>
#include <string>

// ── Helpers ───────────────────────────────────────────────────────────────────

namespace
{

/// Look up the virtual address of an exported function using LIEF's abstract
/// Binary::get_function_address().  Returns nullopt when the symbol is absent.
std::optional<uint64_t> find_export_va(LIEF::Binary &binary,
                                       const std::string  &sym_name)
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

} // anonymous namespace

// ── Test ──────────────────────────────────────────────────────────────────────

#ifndef EVAL_TWO_FUNCS_SO
#  error "EVAL_TWO_FUNCS_SO must be defined at compile time (path to libeval-two-funcs.so)"
#endif

TEST(lifter_multi_function_lift)
{
    // ── Setup ────────────────────────────────────────────────────────────────

    const char *so_path = EVAL_TWO_FUNCS_SO;

    auto binary = LIEF::Parser::parse(so_path);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    // Resolve both entry points — use LIEF directly before moving into BinaryContext.
    auto va_a = find_export_va(*binary, "func_a");
    auto va_b = find_export_va(*binary, "func_b");
    CHECK(va_a.has_value());
    CHECK(va_b.has_value());
    if (!va_a || !va_b)
        return;

    CHECK(*va_a != *va_b);

    // ── Create Lifter ────────────────────────────────────────────────────────

    llvm::LLVMContext ctx;
    auto arch = remill::Arch::Get(
        ctx, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
    CHECK(arch != nullptr);
    if (!arch)
        return;

    lifted::BinaryContext bin_ctx(std::move(binary));
    auto make_entry_annotation = [&]() {
        auto ann = std::make_unique<lifted::fnc_annotation_t>();
        ann->cc = &lifted::abi::SystemVx64CC::get();
        return bin_ctx.add_annotation(std::move(ann));
    };
    lifted::lifter::standard_lifter_config_t cb_config{};
    lifted::lifter::StandardLifterCallbacks callbacks(std::move(cb_config));

    auto lifter_or = lifted::lifter::Lifter::create(arch.get(), bin_ctx, &callbacks);
    CHECK(static_cast<bool>(lifter_or));
    if (!lifter_or)
    {
        llvm::consumeError(lifter_or.takeError());
        return;
    }
    auto &lifter = *lifter_or;

    // ── Lift func_a ──────────────────────────────────────────────────────────

    auto entry_a_annotation = make_entry_annotation();
    auto result_a = lifter.lift(*va_a, entry_a_annotation);
    CHECK(static_cast<bool>(result_a));
    if (!result_a)
    {
        llvm::consumeError(result_a.takeError());
        return;
    }
    CHECK(result_a->lifted_function != nullptr);
    CHECK(result_a->stats.bbs_lifted >= 1);
    CHECK(!result_a->basic_blocks.empty());
    CHECK(unwrapExpected(lifted::abi::get_state_form(*result_a->lifted_function)) ==
          lifted::abi::state_form_t::folded);
    CHECK(unwrapExpected(lifted::abi::get_annotation_id(*result_a->lifted_function)) == entry_a_annotation);

    // ── Lift func_b ──────────────────────────────────────────────────────────

    auto entry_b_annotation = make_entry_annotation();
    auto result_b = lifter.lift(*va_b, entry_b_annotation);
    CHECK(static_cast<bool>(result_b));
    if (!result_b)
    {
        llvm::consumeError(result_b.takeError());
        return;
    }
    CHECK(result_b->lifted_function != nullptr);
    CHECK(result_b->stats.bbs_lifted >= 1);
    CHECK(result_b->stats.bbs_total >= 1);
    CHECK(!result_b->basic_blocks.empty());
    CHECK(unwrapExpected(lifted::abi::get_state_form(*result_b->lifted_function)) ==
          lifted::abi::state_form_t::folded);
    CHECK(unwrapExpected(lifted::abi::get_annotation_id(*result_b->lifted_function)) == entry_b_annotation);

    // ── Verify BB cache is shared across calls ───────────────────────────────

    // After lifting both functions, explored() must contain entries from both.
    const auto &cache = lifter.explored();
    CHECK(cache.size() >= 2);

    // The first function's entry point must be in the cache.
    CHECK(cache.count(*va_a) > 0);
    CHECK(cache.count(*va_b) > 0);

    // ── Re-lift func_a to confirm cache is used ──────────────────────────────

    auto entry_a2_annotation = make_entry_annotation();
    auto result_a2 = lifter.lift(*va_a, entry_a2_annotation);
    CHECK(static_cast<bool>(result_a2));
    if (!result_a2)
    {
        llvm::consumeError(result_a2.takeError());
        return;
    }
    CHECK(result_a2->lifted_function != nullptr);
    CHECK(result_a2->stats.bbs_cached >= 1);
    CHECK(unwrapExpected(lifted::abi::get_state_form(*result_a2->lifted_function)) ==
          lifted::abi::state_form_t::folded);
    CHECK(unwrapExpected(lifted::abi::get_annotation_id(*result_a2->lifted_function)) == entry_a2_annotation);
}
