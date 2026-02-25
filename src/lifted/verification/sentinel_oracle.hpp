#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <algorithm>

namespace lifted::verification
{
    // A sentinel to inject into random memory reads.
    // size_bytes: 0 = wildcard (matches any read size, value is zero-extended/truncated),
    //             1, 2, 4, 8 = exact read size match.
    // value:      the value to inject (masked to size_bytes width at injection time).
    // inv_prob:   1-in-N base probability of this sentinel firing.
    struct sentinel_t
    {
        uint8_t size_bytes; // 0 = any, 1, 2, 4, 8
        uint64_t value;
        uint32_t inv_prob; // must be >= 1
    };

    // Oracle that determines whether (and which) sentinel to inject for a given read slot.
    //
    // Selection model: fixed denominator D = 2^32, no LCM.
    // Each sentinel gets a slice of width floor(D / (inv_prob_i * scale)).
    // A single draw r = (uint32_t)slot_seed selects at most one sentinel.
    // List order does NOT affect per-sentinel probability — only inv_prob and scale do.
    //
    // Two independent draws per query:
    //   lower 32 bits of slot_seed  → exact-size group
    //   upper 32 bits of slot_seed  → wildcard (size=0) group
    // This keeps the two groups statistically independent.
    //
    // Call recompute() after any mutation to sentinels or scale.
    class sentinel_oracle
    {
    public:
        std::vector<sentinel_t> sentinels;
        uint32_t scale = 1; // global inv_prob multiplier (larger = rarer)

        sentinel_oracle() = default;

        sentinel_oracle(std::vector<sentinel_t> s, uint32_t sc = 1)
            : sentinels(std::move(s)), scale(sc)
        {
            recompute();
        }

        void recompute()
        {
            for (auto &g : groups_)
                g = {};

            for (uint8_t sent_idx = 0; sent_idx < sentinels.size(); ++sent_idx)
            {
                const auto &s = sentinels[sent_idx];
                int gi = size_to_group_idx(s.size_bytes);
                if (gi < 0)
                    continue;

                // Effective denominator D = 2^32.
                // Slice = floor(2^32 / (inv_prob * scale)).
                uint64_t denom = (uint64_t)std::max(1u, s.inv_prob) * (uint64_t)std::max(1u, scale);
                // When denom==1 the true slice is 2^32, which overflows uint32_t to 0.
                // Use UINT32_MAX (~100%) instead so it behaves as "always fire".
                uint32_t slice = (denom <= 1) ? UINT32_MAX : (uint32_t)(0x100000000ULL / denom);
                if (slice == 0)
                    continue; // probability rounds to zero — sentinel never fires

                auto &g = groups_[gi];
                uint32_t new_total = g.total + slice;
                if (new_total < g.total)
                    new_total = UINT32_MAX; // saturate rather than overflow
                g.cdf.push_back({new_total, sent_idx});
                g.total = new_total;
            }
        }

        // Query for a given slot seed and requested read size.
        // Returns the sentinel to inject, or nullopt.
        // value in the returned sentinel is already masked/zero-extended to size_bytes.
        std::optional<sentinel_t> query(uint64_t slot_seed, uint8_t size_bytes) const
        {
            uint32_t r_exact = (uint32_t)slot_seed;        // lower 32 bits
            uint32_t r_wild = (uint32_t)(slot_seed >> 32); // upper 32 bits

            int exact_gi = size_to_group_idx(size_bytes);
            if (exact_gi > 0) // exact_gi == 0 would be the wildcard group itself
            {
                const auto &g = groups_[exact_gi];
                if (g.total > 0 && r_exact < g.total)
                {
                    for (const auto &e : g.cdf)
                    {
                        if (r_exact < e.cumulative_threshold)
                        {
                            sentinel_t result = sentinels[e.sentinel_idx];
                            result.value = mask_to_size(result.value, size_bytes);
                            result.size_bytes = size_bytes;
                            return result;
                        }
                    }
                }
            }

            // Wildcard group (size_bytes == 0 sentinels)
            const auto &wg = groups_[0];
            if (wg.total > 0 && r_wild < wg.total)
            {
                for (const auto &e : wg.cdf)
                {
                    if (r_wild < e.cumulative_threshold)
                    {
                        sentinel_t result = sentinels[e.sentinel_idx];
                        result.value = mask_to_size(result.value, size_bytes);
                        result.size_bytes = size_bytes;
                        return result;
                    }
                }
            }

            return std::nullopt;
        }

    private:
        // CDF entry: cumulative upper bound (exclusive) for a sentinel's slice.
        struct cdf_entry_t
        {
            uint32_t cumulative_threshold;
            uint8_t sentinel_idx;
        };

        // One group per supported size: index 0=wildcard, 1=size1, 2=size2, 3=size4, 4=size8.
        struct size_group_t
        {
            std::vector<cdf_entry_t> cdf;
            uint32_t total = 0;
        };
        size_group_t groups_[5];

        static int size_to_group_idx(uint8_t size_bytes)
        {
            switch (size_bytes)
            {
            case 0:
                return 0;
            case 1:
                return 1;
            case 2:
                return 2;
            case 4:
                return 3;
            case 8:
                return 4;
            default:
                return -1; // unsupported
            }
        }

        static uint64_t mask_to_size(uint64_t value, uint8_t size_bytes)
        {
            if (size_bytes == 0 || size_bytes >= 8)
                return value;
            uint64_t mask = (1ULL << (size_bytes * 8)) - 1ULL;
            return value & mask;
        }
    };

} // namespace lifted::verification
