#include "test_framework.hpp"

#include "compat/lief_compat.hpp"
#include "utils.hpp"

#include <filesystem>
#include <memory>

#if defined(EVAL_ARITHMETIC_POLARIS_SO) || defined(EVAL_BKDRHASH_POLARIS_SO)
namespace
{
std::unique_ptr<LIEF::Binary> load_binary(const std::filesystem::path &path)
{
    auto binary = LIEF::Parser::parse(path);
    CHECK(binary != nullptr);
    return binary;
}
} // namespace
#endif

#if defined(EVAL_ARITHMETIC_POLARIS_SO)
TEST(elf_relocations_resolve_arithmetic_got_slots)
{
    auto binary = load_binary(EVAL_ARITHMETIC_POLARIS_SO);
    if (!binary)
        return;

    auto x_ptr = lifted::utils::read_elf_relocated_word64(*binary, 0x3fc8, 0);
    auto y3_ptr = lifted::utils::read_elf_relocated_word64(*binary, 0x3fd0, 0);
    auto imported = lifted::utils::read_elf_relocated_word64(*binary, 0x3ff8, 0);
    auto x_ptr_loaded = lifted::utils::read_elf_relocated_word64(*binary, 0x3fc8, 0x700000000000ULL);

    CHECK(x_ptr.has_value());
    CHECK(y3_ptr.has_value());
    CHECK(!imported.has_value());
    CHECK(x_ptr_loaded.has_value());
    if (!x_ptr || !y3_ptr || !x_ptr_loaded)
        return;

    CHECK_EQ(*x_ptr, 0x402cULL);
    CHECK_EQ(*y3_ptr, 0x4030ULL);
    CHECK_EQ(*x_ptr_loaded, 0x700000000000ULL + 0x402cULL);
}
#endif

#if defined(EVAL_BKDRHASH_POLARIS_SO)
TEST(elf_relocations_resolve_bkdrhash_data_slot)
{
    auto binary = load_binary(EVAL_BKDRHASH_POLARIS_SO);
    if (!binary)
        return;

    constexpr uint64_t kSlotRva = 0x4040ULL;
    constexpr uint64_t kBkdrHashRva = 0x1120ULL;
    constexpr uint64_t kAddend = 0x3dbfd740ULL;
    constexpr uint64_t kLoadBase = 0x400000000000ULL;

    auto raw = lifted::utils::read_elf_relocated_word64(*binary, kSlotRva, 0);
    auto loaded = lifted::utils::read_elf_relocated_word64(*binary, kSlotRva, kLoadBase);

    CHECK(raw.has_value());
    CHECK(loaded.has_value());
    if (!raw || !loaded)
        return;

    CHECK_EQ(*raw, kBkdrHashRva + kAddend);
    CHECK_EQ(*loaded, kLoadBase + kBkdrHashRva + kAddend);
}
#endif
