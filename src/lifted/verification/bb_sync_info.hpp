#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace lifted::verification
{
    struct bb_sync_range_t
    {
        uint64_t start = 0;
        uint64_t end = 0;

        [[nodiscard]] bool contains(uint64_t rva) const noexcept
        {
            return start <= rva && rva < end;
        }
    };

    /// Structural block-partition metadata shared across executors/visualizers.
    /// This stays toolchain-neutral: plain RVA half-open ranges only.
    struct bb_sync_info_t
    {
        std::vector<bb_sync_range_t> real_blocks;

        [[nodiscard]] std::optional<uint64_t> canonicalize_rva(uint64_t raw_rva) const noexcept
        {
            auto it = std::upper_bound(
                real_blocks.begin(), real_blocks.end(), raw_rva,
                [](uint64_t rva, const bb_sync_range_t &range)
                {
                    return rva < range.start;
                });
            if (it == real_blocks.begin())
                return std::nullopt;

            --it;
            if (!it->contains(raw_rva))
                return std::nullopt;

            return it->start;
        }

        [[nodiscard]] std::vector<uint64_t> block_starts_in_range(uint64_t begin_rva, uint64_t end_rva) const
        {
            std::vector<uint64_t> starts;
            if (begin_rva >= end_rva)
                return starts;

            auto it = std::lower_bound(
                real_blocks.begin(), real_blocks.end(), begin_rva,
                [](const bb_sync_range_t &range, uint64_t rva)
                {
                    return range.start < rva;
                });

            for (; it != real_blocks.end() && it->start < end_rva; ++it)
                starts.push_back(it->start);

            return starts;
        }
    };
}
