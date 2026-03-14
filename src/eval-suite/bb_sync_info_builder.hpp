#pragma once

#include "lifter/lifter_types.hpp"
#include "verification/bb_sync_info.hpp"

#include <algorithm>
#include <set>

namespace lifted::eval
{
    inline verification::bb_sync_info_t
    make_bb_sync_info(const std::set<lifter::lifted_bb_t> &basic_blocks)
    {
        verification::bb_sync_info_t info;
        info.real_blocks.reserve(basic_blocks.size());

        for (const auto &bb : basic_blocks)
        {
            if (bb.type != lifter::lifted_bb_t::Type::REAL || !bb.rva_range)
                continue;

            info.real_blocks.push_back({
                .start = bb.rva_range->start(),
                .end = bb.rva_range->end(),
            });
        }

        std::sort(info.real_blocks.begin(), info.real_blocks.end(),
                  [](const verification::bb_sync_range_t &lhs,
                     const verification::bb_sync_range_t &rhs)
                  {
                      return lhs.start < rhs.start;
                  });
        return info;
    }
}
