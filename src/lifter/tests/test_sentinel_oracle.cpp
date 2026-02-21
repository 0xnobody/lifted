#include "test_framework.hpp"
#include "verification/sentinel_oracle.hpp"

#include <lifted/hash_mix.hpp>

#include <cstdint>
#include <cmath>
#include <limits>

using namespace lifted::verification;

// ── Helpers ───────────────────────────────────────────────────────────────────

// Mix a sequential seed into a well-distributed uint64_t,
// approximating the distribution of compute_oracle_slot_seed outputs.
static uint64_t spread(uint64_t s)
{
    return lifted::hash::mix(0ULL, s);
}

// Count how many times each sentinel value fires over [0, num_seeds).
// Seeds are spread across the full uint64_t range so CDF coverage is uniform.
// Returns {count_for_value_a, count_for_value_b}.
static std::pair<int, int> count_fires_ab(sentinel_oracle oracle,
                                          uint8_t size,
                                          uint64_t val_a,
                                          uint64_t val_b,
                                          uint64_t num_seeds)
{
    int ca = 0, cb = 0;
    for (uint64_t s = 0; s < num_seeds; ++s)
    {
        auto r = oracle.query(spread(s), size);
        if (!r)
            continue;
        if (r->value == val_a)
            ++ca;
        else if (r->value == val_b)
            ++cb;
    }
    return {ca, cb};
}

// ── Tests ─────────────────────────────────────────────────────────────────────

TEST(always_fire_sentinel_fires_for_all_seeds)
{
    // inv_prob=1, scale=1 → slice = 2^32/1 = 2^32, which saturates the whole draw space.
    sentinel_oracle oracle({sentinel_t{.size_bytes = 1, .value = 0xAA, .inv_prob = 1}}, 1);
    for (uint64_t seed = 0; seed < 1000; ++seed)
    {
        auto r = oracle.query(seed, 1);
        CHECK(r.has_value());
        CHECK_EQ(r->value, 0xAAULL);
        CHECK_EQ(r->size_bytes, 1);
    }
}

TEST(always_fire_returns_correct_size_bytes_field)
{
    sentinel_oracle oracle({sentinel_t{.size_bytes = 4, .value = 0xDEADBEEF, .inv_prob = 1}}, 1);
    auto r = oracle.query(0, 4);
    CHECK(r.has_value());
    CHECK_EQ(r->size_bytes, 4);
    CHECK_EQ(r->value, 0xDEADBEEFULL);
}

TEST(zero_probability_sentinel_never_fires)
{
    // inv_prob=UINT32_MAX, scale=2 → denom = 2*UINT32_MAX ≈ 8.6e9
    // slice = floor(2^32 / 8.6e9) = 0 → sentinel never fires.
    sentinel_oracle oracle({sentinel_t{.size_bytes = 1, .value = 0xFF, .inv_prob = std::numeric_limits<uint32_t>::max()}}, 2);
    int fires = 0;
    for (uint64_t seed = 0; seed < 100000; ++seed)
        if (oracle.query(seed, 1).has_value())
            ++fires;
    CHECK_EQ(fires, 0);
}

TEST(size_mismatch_does_not_fire_via_exact_group)
{
    // Sentinel is size=4; queried for size=1. No wildcard → should never fire.
    sentinel_oracle oracle({sentinel_t{.size_bytes = 4, .value = 0xDEADBEEF, .inv_prob = 1}}, 1);
    for (uint64_t seed = 0; seed < 200; ++seed)
        CHECK(!oracle.query(seed, 1).has_value());
}

TEST(wildcard_sentinel_fires_for_every_read_size)
{
    // size_bytes=0 (wildcard), inv_prob=1 → always fires for any queried size.
    sentinel_oracle oracle({sentinel_t{.size_bytes = 0, .value = 0xFFFFFFFFFFFFFFFFULL, .inv_prob = 1}}, 1);
    for (uint8_t sz : {(uint8_t)1, (uint8_t)2, (uint8_t)4, (uint8_t)8})
    {
        auto r = oracle.query(0xABCDEF, sz);
        CHECK(r.has_value());
        // Value is masked to the requested size.
        uint64_t expected = (sz >= 8) ? 0xFFFFFFFFFFFFFFFFULL : ((1ULL << (sz * 8)) - 1ULL);
        CHECK_EQ(r->value, expected);
    }
}

TEST(wildcard_fires_for_unsupported_size_value_masked)
{
    // Wildcard (size_bytes=0) is consulted for any query size, including unusual ones like 3.
    // mask_to_size(0xFF, 3) = 0xFF & 0xFFFFFF = 0xFF (the value 0xFF has no high bytes to mask).
    sentinel_oracle oracle({sentinel_t{.size_bytes = 0, .value = 0xFF, .inv_prob = 1}}, 1);
    auto r = oracle.query(0, 3);
    CHECK(r.has_value());
    CHECK_EQ(r->value, 0xFFULL); // 0xFF masked to 3 bytes is still 0xFF
}

TEST(value_masked_to_read_size_for_exact_group)
{
    sentinel_oracle oracle({sentinel_t{.size_bytes = 1, .value = 0xDEADBEEFCAFEBABEULL, .inv_prob = 1}}, 1);
    auto r = oracle.query(0, 1);
    CHECK(r.has_value());
    CHECK_EQ(r->value, 0xBEULL); // low byte of DEADBEEFCAFEBABE
}

TEST(value_masked_to_read_size_for_wildcard_group)
{
    sentinel_oracle oracle({sentinel_t{.size_bytes = 0, .value = 0xDEADBEEFCAFEBABEULL, .inv_prob = 1}}, 1);
    // Upper 32 bits of seed are the wildcard draw (r_wild).
    // Avoid 0xFFFFFFFF in upper bits: that's the one value not < UINT32_MAX (always-fire total).
    auto r = oracle.query(0xFFFFFFFE00000000ULL, 2);
    CHECK(r.has_value());
    CHECK_EQ(r->value, 0xBABEULL); // low 2 bytes of DEADBEEFCAFEBABE
}

TEST(scale_reduces_fire_rate)
{
    // Both oracles: same sentinel, inv_prob=2. High scale makes it 4x rarer.
    sentinel_oracle lo({sentinel_t{.size_bytes = 1, .value = 0x11, .inv_prob = 2}}, 1);
    sentinel_oracle hi({sentinel_t{.size_bytes = 1, .value = 0x11, .inv_prob = 2}}, 4);

    int fires_lo = 0, fires_hi = 0;
    constexpr int N = 200000;
    // Use spread() so seeds cover the full uint64_t range uniformly,
    // mirroring what compute_oracle_slot_seed produces in practice.
    for (uint64_t s = 0; s < N; ++s)
    {
        if (lo.query(spread(s), 1))
            ++fires_lo;
        if (hi.query(spread(s), 1))
            ++fires_hi;
    }
    // hi should fire ~4x less than lo
    // Allow 2x–8x ratio to account for hash distribution.
    CHECK_GT(fires_lo, fires_hi);
    CHECK(fires_lo > fires_hi * 2);
    CHECK(fires_lo < fires_hi * 8);
}

TEST(list_order_does_not_bias_distribution)
{
    // Sentinel A: inv_prob=2, sentinel B: inv_prob=4.
    // A fires ~2x as often as B regardless of list order.
    constexpr uint32_t VAL_A = 0xAAAA;
    constexpr uint32_t VAL_B = 0xBBBB;
    constexpr int N = 500000;

    auto [a1, b1] = count_fires_ab(
        sentinel_oracle({{4, VAL_A, 2}, {4, VAL_B, 4}}, 1), 4, VAL_A, VAL_B, N);
    auto [a2, b2] = count_fires_ab(
        sentinel_oracle({{4, VAL_B, 4}, {4, VAL_A, 2}}, 1), 4, VAL_A, VAL_B, N);

    // Both should fire (not degenerate)
    CHECK_GT(a1, 0);
    CHECK_GT(b1, 0);
    CHECK_GT(a2, 0);
    CHECK_GT(b2, 0);

    double ratio1 = static_cast<double>(a1) / static_cast<double>(b1);
    double ratio2 = static_cast<double>(a2) / static_cast<double>(b2);

    // Each ratio should be ~2 (A fires 2x more often than B).
    CHECK(ratio1 > 1.5 && ratio1 < 2.5);
    CHECK(ratio2 > 1.5 && ratio2 < 2.5);

    // The two orderings should produce consistent ratios (within 40% of each other).
    CHECK(std::abs(ratio1 - ratio2) < 0.8);
}

TEST(recompute_after_mutation_takes_effect)
{
    sentinel_oracle oracle({sentinel_t{.size_bytes = 1, .value = 0xAA, .inv_prob = 1}}, 1);

    // Before mutation: always fires.
    CHECK(oracle.query(0, 1).has_value());

    // Mutate inv_prob to make it extremely rare, then recompute.
    oracle.sentinels[0].inv_prob = std::numeric_limits<uint32_t>::max();
    oracle.scale = 2;
    oracle.recompute();

    // Should no longer fire.
    int fires = 0;
    for (uint64_t s = 0; s < 10000; ++s)
        if (oracle.query(s, 1).has_value())
            ++fires;
    CHECK_EQ(fires, 0);
}

TEST(exact_and_wildcard_are_independent_draws)
{
    // One exact-size=1 sentinel (fires on lower 32 bits) and
    // one wildcard sentinel (fires on upper 32 bits).
    // Use seeds crafted so only one half fires.

    sentinel_oracle oracle(
        {
            sentinel_t{.size_bytes = 1, .value = 0x11, .inv_prob = 1}, // exact: always fires via lower bits
            sentinel_t{.size_bytes = 0, .value = 0x22, .inv_prob = 1}, // wildcard: always fires via upper bits
        },
        1);

    // Since exact group always fires (inv_prob=1), size=1 returns the exact sentinel (0x11).
    auto r = oracle.query(0xDEAD'BEEF'0000'0000ULL, 1);
    CHECK(r.has_value());
    // Exact group wins for size=1 query (checked first).
    CHECK_EQ(r->value, 0x11ULL);

    // For size=2 (no exact sentinel), wildcard catches it.
    auto r2 = oracle.query(0xDEAD'BEEF'0000'0000ULL, 2);
    CHECK(r2.has_value());
    CHECK_EQ(r2->value, 0x22ULL);
}

TEST(empty_oracle_never_fires)
{
    sentinel_oracle oracle;
    for (uint64_t s = 0; s < 1000; ++s)
        for (uint8_t sz : {(uint8_t)1, (uint8_t)2, (uint8_t)4, (uint8_t)8})
            CHECK(!oracle.query(s, sz).has_value());
}
