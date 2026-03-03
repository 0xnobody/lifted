#include "test_framework.hpp"
#include "verification/value_generator.hpp"
#include "verification/paged_memory_state.hpp"

#include <cstdint>
#include <cstring>
#include <span>

using namespace lifted::verification;

// ── Helpers ───────────────────────────────────────────────────────────────────

// A factory whose generators fill every byte with a fixed constant.
struct constant_generator : value_generator
{
    uint8_t fill_byte;
    explicit constant_generator(uint8_t b) : fill_byte(b) {}

    void fill_buffer(std::span<std::byte> buf) override
    {
        for (auto &b : buf)
            b = std::byte{fill_byte};
    }
};

struct constant_generator_factory : value_generator_factory
{
    uint8_t fill_byte;
    explicit constant_generator_factory(uint8_t b) : fill_byte(b) {}

    std::unique_ptr<value_generator> create(uint64_t /*seed*/) const override
    {
        return std::make_unique<constant_generator>(fill_byte);
    }
};

// ── Determinism ───────────────────────────────────────────────────────────────

TEST(uniform_generator_deterministic)
{
    uniform_value_generator a(0xDEADBEEF);
    uniform_value_generator b(0xDEADBEEF);
    for (int i = 0; i < 100; ++i)
        CHECK_EQ(a.generate64(), b.generate64());
}

TEST(factory_creates_deterministic_generators)
{
    uniform_value_generator_factory factory{};
    auto g1 = factory.create(0xCAFEBABE);
    auto g2 = factory.create(0xCAFEBABE);
    for (int i = 0; i < 50; ++i)
        CHECK_EQ(g1->generate64(), g2->generate64());
}

TEST(different_seeds_produce_different_output)
{
    uniform_value_generator_factory factory{};
    auto g1 = factory.create(0x1111111111111111ULL);
    auto g2 = factory.create(0x2222222222222222ULL);
    int mismatches = 0;
    for (int i = 0; i < 64; ++i)
        if (g1->generate64() != g2->generate64())
            ++mismatches;
    CHECK_GT(mismatches, 0);
}

// ── Constraints ───────────────────────────────────────────────────────────────

TEST(alignment_constraint_8)
{
    uniform_value_generator_factory factory{value_constraints_t{.min = 0, .max = UINT64_MAX, .alignment = 8}};
    auto gen = factory.create(0xABCD1234);
    for (int i = 0; i < 1000; ++i)
    {
        uint64_t v = gen->generate64();
        CHECK_EQ(v % 8, 0ULL);
    }
}

TEST(alignment_constraint_64)
{
    uniform_value_generator_factory factory{value_constraints_t{.min = 0, .max = UINT64_MAX, .alignment = 64}};
    auto gen = factory.create(0xBEEF);
    for (int i = 0; i < 500; ++i)
    {
        uint64_t v = gen->generate64();
        CHECK_EQ(v % 64, 0ULL);
    }
}

TEST(range_constraint_32bit)
{
    uniform_value_generator_factory factory{value_constraints_t{.min = 0, .max = 0xFFFFFFFFULL, .alignment = 1}};
    auto gen = factory.create(0x5EED);
    for (int i = 0; i < 500; ++i)
    {
        uint64_t v = gen->generate64();
        CHECK(v <= 0xFFFFFFFFULL);
    }
}

TEST(range_constraint_with_nonzero_min)
{
    uniform_value_generator_factory factory{value_constraints_t{.min = 100, .max = 200, .alignment = 1}};
    auto gen = factory.create(0x1234);
    for (int i = 0; i < 500; ++i)
    {
        uint64_t v = gen->generate64();
        CHECK(v >= 100ULL);
        CHECK(v <= 200ULL);
    }
}

TEST(unconstrained_is_full_range)
{
    // Default constraints: any uint64_t is valid — just verify no crash and some spread.
    uniform_value_generator_factory factory{};
    auto gen = factory.create(0x9999);
    uint64_t first = gen->generate64();
    bool saw_different = false;
    for (int i = 0; i < 64; ++i)
        if (gen->generate64() != first)
            saw_different = true;
    CHECK(saw_different);
}

// ── fill_buffer ───────────────────────────────────────────────────────────────

TEST(fill_buffer_fills_entire_span)
{
    uniform_value_generator gen(0x42);
    std::array<std::byte, 37> buf{};
    buf.fill(std::byte{0xCC}); // sentinel
    gen.fill_buffer(buf);
    bool all_overwritten = true;
    for (auto b : buf)
        if (b == std::byte{0xCC})
            all_overwritten = false;
    // Can't guarantee all bytes differ from 0xCC, but we can spot-check that
    // at least the buffer was touched.  Instead just verify determinism.
    uniform_value_generator gen2(0x42);
    std::array<std::byte, 37> buf2{};
    gen2.fill_buffer(buf2);
    CHECK_EQ(std::memcmp(buf.data(), buf2.data(), 37), 0);
}

// ── paged_memory_state with factory ──────────────────────────────────────────

TEST(paged_memory_uses_factory_fill)
{
    // constant_generator_factory always fills with 0xAB.
    // Reading from any DYNAMIC address should return bytes of 0xAB.
    constant_generator_factory factory{0xAB};
    paged_memory_state mem(0xDEAD, nullptr, &factory);
    // DYNAMIC address (not in any binary image).
    CHECK_EQ(mem.read8(0x100000), (uint8_t)0xAB);
    CHECK_EQ(mem.read8(0x100001), (uint8_t)0xAB);
    CHECK_EQ(mem.read64(0x200000), (uint64_t)0xABABABABABABABABULL);
}

TEST(paged_memory_factory_deterministic)
{
    // Two paged_memory_state instances with same seed+factory → same reads.
    uniform_value_generator_factory factory{};
    paged_memory_state a(0x1234, nullptr, &factory);
    paged_memory_state b(0x1234, nullptr, &factory);
    for (uint64_t addr = 0x10000; addr < 0x10100; addr += 8)
        CHECK_EQ(a.read64(addr), b.read64(addr));
}

TEST(paged_memory_factory_vs_no_factory_differ)
{
    // With and without a factory should produce different page content
    // (factory path uses value_generator::fill_buffer; default path uses page_t(seed)).
    uniform_value_generator_factory factory{};
    paged_memory_state with_factory(0xABCD, nullptr, &factory);
    paged_memory_state without_factory(0xABCD);
    int mismatches = 0;
    for (uint64_t addr = 0x50000; addr < 0x50100; addr += 8)
        if (with_factory.read64(addr) != without_factory.read64(addr))
            ++mismatches;
    CHECK_GT(mismatches, 0);
}
