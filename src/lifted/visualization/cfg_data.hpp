#pragma once

#include "lifter/lifter_types.hpp"

#include <map>
#include <set>
#include <string>

namespace lifted::visualization {

/// Immutable snapshot of a lifted function's CFG — all the data needed for
/// visualization without the heavy LLVM Module.
struct CfgSnapshot {
    std::set<lifter::edge_t>                               edges;
    std::set<lifter::lifted_bb_t>                          basic_blocks;
    std::map<lifter::bb_id_t, lifter::synthetic_block_info_t> synthetic_blocks;
    uint64_t    entry_rva  = 0;
    std::string func_name;
};

/// Build a snapshot from a lift result.  Copies the lightweight fields;
/// the Module (which may already be moved) is not referenced.
inline CfgSnapshot make_cfg_snapshot(const lifter::lift_result_t &lr,
                                     uint64_t     entry_rva,
                                     std::string  func_name = {})
{
    return {
        .edges            = lr.edges,
        .basic_blocks     = lr.basic_blocks,
        .synthetic_blocks = lr.synthetic_blocks,
        .entry_rva        = entry_rva,
        .func_name        = std::move(func_name),
    };
}

} // namespace lifted::visualization
