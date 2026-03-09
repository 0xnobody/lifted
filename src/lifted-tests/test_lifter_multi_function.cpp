#include "test_framework.hpp"

#include "compat/lief_compat.hpp" // must be first: saves+undefines DEBUG before any glog header

#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"
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

    lifted::abi::SystemVx64CC CC;
    lifted::BinaryContext bin_ctx(std::move(binary));
    lifted::lifter::standard_lifter_config_t cb_config{
        .default_cc = &CC,
    };
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

    auto result_a = lifter.lift(*va_a);
    CHECK(static_cast<bool>(result_a));
    if (!result_a)
    {
        llvm::consumeError(result_a.takeError());
        return;
    }
    CHECK(result_a->lifted_function != nullptr);
    CHECK(result_a->stats.bbs_lifted >= 1);
    CHECK(result_a->stats.bbs_cached == 0); // first lift: nothing cached yet
    CHECK(!result_a->basic_blocks.empty());

    // ── Lift func_b ──────────────────────────────────────────────────────────

    auto result_b = lifter.lift(*va_b);
    CHECK(static_cast<bool>(result_b));
    if (!result_b)
    {
        llvm::consumeError(result_b.takeError());
        return;
    }
    CHECK(result_b->lifted_function != nullptr);
    CHECK(result_b->stats.bbs_lifted >= 1);
    // func_b has a branch, so >= 2 BBs.
    CHECK(result_b->stats.bbs_total >= 2);
    CHECK(!result_b->basic_blocks.empty());

    // ── Verify BB cache is shared across calls ───────────────────────────────

    // After lifting both functions, explored() must contain entries from both.
    const auto &cache = lifter.explored();
    CHECK(cache.size() >= 2);

    // The first function's entry point must be in the cache.
    CHECK(cache.count(*va_a) > 0);
    CHECK(cache.count(*va_b) > 0);

    // ── Re-lift func_a to confirm cache is used ──────────────────────────────

    auto result_a2 = lifter.lift(*va_a);
    CHECK(static_cast<bool>(result_a2));
    if (!result_a2)
    {
        llvm::consumeError(result_a2.takeError());
        return;
    }
    CHECK(result_a2->lifted_function != nullptr);
    // All BBs should come from cache on re-lift of the same entry point.
    CHECK(result_a2->stats.bbs_lifted == 0);
    CHECK(result_a2->stats.bbs_cached >= 1);
}
