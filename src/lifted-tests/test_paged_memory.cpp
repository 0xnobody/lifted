#include "test_framework.hpp"
#include "verification/paged_memory_state.hpp"

#include <cstdint>

using namespace lifted::verification;

// ── Helpers ───────────────────────────────────────────────────────────────────

static sentinel_oracle make_oracle_8(uint8_t val)
{
    return sentinel_oracle({sentinel_t{.size_bytes = 1, .value = val, .inv_prob = 1}}, 1);
}

static sentinel_oracle make_oracle_16(uint16_t val)
{
    return sentinel_oracle({sentinel_t{.size_bytes = 2, .value = val, .inv_prob = 1}}, 1);
}

static sentinel_oracle make_oracle_32(uint32_t val)
{
    return sentinel_oracle({sentinel_t{.size_bytes = 4, .value = val, .inv_prob = 1}}, 1);
}

static sentinel_oracle make_oracle_64(uint64_t val)
{
    return sentinel_oracle({sentinel_t{.size_bytes = 8, .value = val, .inv_prob = 1}}, 1);
}

// ── No-oracle baseline ────────────────────────────────────────────────────────

TEST(no_oracle_reads_are_deterministic)
{
    // Same address, same seed → same value on every read.
    paged_memory_state mem(0x1234567890ABCDEFULL);
    uint8_t v1 = mem.read8(0x10000);
    uint8_t v2 = mem.read8(0x10000);
    CHECK_EQ(v1, v2);
}

TEST(two_instances_same_seed_produce_same_reads)
{
    paged_memory_state a(0xDEADBEEFCAFEBABEULL);
    paged_memory_state b(0xDEADBEEFCAFEBABEULL);
    for (uint64_t addr = 0x20000; addr < 0x20100; addr += 8)
        CHECK_EQ(a.read64(addr), b.read64(addr));
}

TEST(different_seeds_produce_different_reads)
{
    paged_memory_state a(0x1111111111111111ULL);
    paged_memory_state b(0x2222222222222222ULL);
    // Very unlikely all 64 reads are identical for different seeds.
    int mismatches = 0;
    for (uint64_t addr = 0x30000; addr < 0x30100; addr += 8)
        if (a.read64(addr) != b.read64(addr))
            ++mismatches;
    CHECK_GT(mismatches, 0);
}

// ── Oracle read8 ──────────────────────────────────────────────────────────────

TEST(oracle_read8_injects_sentinel_value)
{
    paged_memory_state mem(0xAAAA);
    auto oracle = make_oracle_8(0xBB);
    mem.set_oracle(&oracle);
    CHECK_EQ(mem.read8(0x40000), (uint8_t)0xBB);
}

TEST(oracle_read8_is_cached_on_second_read)
{
    paged_memory_state mem(0xAAAA);
    auto oracle = make_oracle_8(0xCC);
    mem.set_oracle(&oracle);
    uint8_t first = mem.read8(0x40010);
    uint8_t second = mem.read8(0x40010);
    CHECK_EQ(first, (uint8_t)0xCC);
    CHECK_EQ(second, (uint8_t)0xCC);
}

TEST(oracle_read8_sentinel_filled_bit_is_set)
{
    paged_memory_state mem(0xAAAA);
    auto oracle = make_oracle_8(0xDD);
    mem.set_oracle(&oracle);
    mem.read8(0x40020);

    const auto &pages = mem.get_pages();
    auto it = pages.find(0x40000);
    CHECK(it != pages.end());
    CHECK(it->second.sentinel_filled.test(0x20)); // offset 0x20 in page
}

TEST(oracle_read8_does_not_set_written_bit)
{
    paged_memory_state mem(0xAAAA);
    auto oracle = make_oracle_8(0xEE);
    mem.set_oracle(&oracle);
    mem.read8(0x40030);

    const auto &pages = mem.get_pages();
    auto it = pages.find(0x40000);
    CHECK(it != pages.end());
    CHECK(!it->second.written.test(0x30));
}

// ── Oracle read16 / read32 / read64 ──────────────────────────────────────────

TEST(oracle_read16_injects_sentinel)
{
    paged_memory_state mem(0xBBBB);
    auto oracle = make_oracle_16(0xABCD);
    mem.set_oracle(&oracle);
    CHECK_EQ(mem.read16(0x50000), (uint16_t)0xABCD);
}

TEST(oracle_read32_injects_sentinel)
{
    paged_memory_state mem(0xCCCC);
    auto oracle = make_oracle_32(0xDEADBEEF);
    mem.set_oracle(&oracle);
    CHECK_EQ(mem.read32(0x60000), (uint32_t)0xDEADBEEF);
}

TEST(oracle_read64_injects_sentinel)
{
    paged_memory_state mem(0xDDDD);
    auto oracle = make_oracle_64(0xCAFEBABEDEAD1234ULL);
    mem.set_oracle(&oracle);
    CHECK_EQ(mem.read64(0x70000), (uint64_t)0xCAFEBABEDEAD1234ULL);
}

TEST(oracle_read32_second_read_returns_same_value)
{
    paged_memory_state mem(0xEEEE);
    auto oracle = make_oracle_32(0x12345678);
    mem.set_oracle(&oracle);
    uint32_t v1 = mem.read32(0x60010);
    uint32_t v2 = mem.read32(0x60010);
    CHECK_EQ(v1, (uint32_t)0x12345678);
    CHECK_EQ(v1, v2);
}

// ── Tier-C: partial fill → oracle blocked ────────────────────────────────────

TEST(partial_fill_read8_then_read32_does_not_overwrite_sentinel_byte)
{
    // Step 1: inject 0xAA at byte 0 via read8.
    paged_memory_state mem(0x9999);
    auto oracle8 = make_oracle_8(0xAA);
    mem.set_oracle(&oracle8);
    uint8_t b0 = mem.read8(0x80000);
    CHECK_EQ(b0, (uint8_t)0xAA);

    // Step 2: switch to always-fire 32-bit oracle (would inject 0xDEADBEEF if unchecked).
    auto oracle32 = make_oracle_32(0xDEADBEEF);
    mem.set_oracle(&oracle32);

    // read32 at same address: byte 0 is sentinel_filled → any_filled=true → skip injection.
    uint32_t v32 = mem.read32(0x80000);

    // Low byte must still be 0xAA, NOT overwritten with 0xBE (low byte of 0xDEADBEEF).
    CHECK_EQ((uint8_t)(v32 & 0xFF), (uint8_t)0xAA);
}

TEST(partial_fill_read32_then_read8_already_cached)
{
    // Inject 4 bytes via read32 first, then read8 at same address uses cache.
    paged_memory_state mem(0x7777);
    auto oracle = make_oracle_32(0xCAFEBABE);
    mem.set_oracle(&oracle);
    uint32_t v32 = mem.read32(0x90000);
    CHECK_EQ(v32, (uint32_t)0xCAFEBABE);

    // Now read8 at the same address: sentinel_filled already set → skip oracle.
    // Value comes from data[] which was set by the 32-bit injection (low byte = 0xBE).
    uint8_t b0 = mem.read8(0x90000);
    CHECK_EQ(b0, (uint8_t)0xBE); // low byte of CAFEBABE
}

// ── Program writes block oracle ───────────────────────────────────────────────

TEST(program_write_prevents_oracle_from_overwriting)
{
    paged_memory_state mem(0x5555);
    mem.write8(0xA0000, 0x42);

    // Attach always-fire oracle; read8 at written address should NOT overwrite 0x42.
    auto oracle = make_oracle_8(0xFF);
    mem.set_oracle(&oracle);
    uint8_t v = mem.read8(0xA0000);
    CHECK_EQ(v, (uint8_t)0x42);

    // written bit must still be set.
    const auto &pages = mem.get_pages();
    CHECK(pages.at(0xA0000).written.test(0));
    // sentinel_filled must NOT be set (oracle was suppressed).
    CHECK(!pages.at(0xA0000).sentinel_filled.test(0));
}

TEST(program_write_in_multibye_span_blocks_read32_oracle)
{
    paged_memory_state mem(0x4444);
    // Write byte 2 of the 4-byte span at 0xB0000.
    mem.write8(0xB0002, 0x77);

    auto oracle = make_oracle_32(0xDEADBEEF);
    mem.set_oracle(&oracle);
    // read32 spans bytes [0,1,2,3]; byte 2 is written → any_filled=true → skip injection.
    uint32_t v = mem.read32(0xB0000);
    // Byte 2 must remain 0x77 (program write), not 0xEF (byte 2 of DEADBEEF).
    CHECK_EQ((uint8_t)((v >> 16) & 0xFF), (uint8_t)0x77);
}

// ── write8 tracking ───────────────────────────────────────────────────────────

TEST(write8_sets_written_bit_not_sentinel_filled)
{
    paged_memory_state mem(0x1234);
    mem.write8(0xC0000, 0xFF);

    const auto &pages = mem.get_pages();
    auto it = pages.find(0xC0000);
    CHECK(it != pages.end());
    CHECK(it->second.written.test(0));
    CHECK(!it->second.sentinel_filled.test(0));
}

// ── Cross-page slow path ──────────────────────────────────────────────────────

TEST(cross_page_read64_injects_per_byte_via_size1_oracle)
{
    // 0x100FFC: bytes [0xFFC..0xFFF] on page 0x100000, bytes [0..3] on page 0x101000.
    // All 8 read8 calls hit the size=1 oracle → all bytes become 0xBB.
    paged_memory_state mem(0x3333);
    auto oracle = make_oracle_8(0xBB);
    mem.set_oracle(&oracle);

    uint64_t v = mem.read64(0x100FFC);
    CHECK_EQ(v, (uint64_t)0xBBBBBBBBBBBBBBBBULL);
}

TEST(cross_page_read64_sentinel_filled_on_both_pages)
{
    paged_memory_state mem(0x2222);
    auto oracle = make_oracle_8(0xCC);
    mem.set_oracle(&oracle);
    mem.read64(0x200FFC);

    const auto &pages = mem.get_pages();

    // Page 0x200000: offsets 0xFFC..0xFFF must be sentinel_filled.
    auto it0 = pages.find(0x200000);
    CHECK(it0 != pages.end());
    for (int i = 0xFFC; i <= 0xFFF; ++i)
        CHECK(it0->second.sentinel_filled.test(i));

    // Page 0x201000: offsets 0..3 must be sentinel_filled.
    auto it1 = pages.find(0x201000);
    CHECK(it1 != pages.end());
    for (int i = 0; i <= 3; ++i)
        CHECK(it1->second.sentinel_filled.test(i));
}

// ── compare() ignores sentinel bytes ─────────────────────────────────────────

TEST(compare_unaffected_by_sentinel_injection)
{
    paged_memory_state a(0xFACE);
    paged_memory_state b(0xFACE);
    auto oracle = make_oracle_8(0xAA);
    a.set_oracle(&oracle);
    b.set_oracle(&oracle);

    // Reads trigger oracle but don't set 'written'.
    a.read8(0xD0000);
    b.read8(0xD0000);

    // No program writes → compare must report equivalent.
    CHECK(paged_memory_state::finalize(std::move(a)).compare(paged_memory_state::finalize(std::move(b))));
}

TEST(compare_detects_program_write_mismatch)
{
    paged_memory_state a(0xFACE);
    paged_memory_state b(0xFACE);

    a.write8(0xE0000, 0x11);
    b.write8(0xE0000, 0x22); // different value

    CHECK(!paged_memory_state::finalize(std::move(a)).compare(paged_memory_state::finalize(std::move(b))));
}

// ── Determinism with oracle ───────────────────────────────────────────────────

TEST(two_instances_same_seed_and_oracle_produce_identical_reads)
{
    paged_memory_state a(0xABCDEF);
    paged_memory_state b(0xABCDEF);
    // Probabilistic oracle (not always-fire) — same RNG draws → same sentinel decisions.
    auto oracle = sentinel_oracle({sentinel_t{.size_bytes = 4, .value = 0xCAFEBABE, .inv_prob = 3}}, 1);
    a.set_oracle(&oracle);
    b.set_oracle(&oracle);

    for (uint64_t addr = 0xF0000; addr < 0xF0100; addr += 4)
        CHECK_EQ(a.read32(addr), b.read32(addr));
}

TEST(attach_oracle_nullopt_disables_oracle)
{
    paged_memory_state mem(0x1234);
    auto oracle = make_oracle_8(0xAA);
    mem.set_oracle(&oracle);

    // Read to materialise + cache the page with sentinel.
    uint8_t v1 = mem.read8(0x110000);
    CHECK_EQ(v1, (uint8_t)0xAA);

    // Remove oracle. Now a fresh address should NOT get sentinel value 0xAA.
    mem.set_oracle(nullptr);
    // Different address (no cached sentinel) — oracle is off, value comes from random data.
    // With high probability it won't be 0xAA; we just verify the oracle won't inject 0xAA
    // on an address that was never accessed before. Check sentinel_filled is NOT set.
    mem.read8(0x120000);
    const auto &pages = mem.get_pages();
    auto it = pages.find(0x120000);
    CHECK(it != pages.end());
    CHECK(!it->second.sentinel_filled.test(0));
}
