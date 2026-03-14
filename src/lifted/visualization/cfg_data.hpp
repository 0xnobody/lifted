#pragma once

#include "binary_context.hpp"
#include "lifter/lifter_types.hpp"

#include <map>
#include <optional>
#include <set>
#include <string>

namespace lifted::visualization {

/// Immutable, annotation-owning copy of a synthetic dispatcher for visualization.
struct SyntheticBlockSnapshot {
    lifter::synthetic_block_info_t::Type type;
    std::optional<uint64_t>              dest_addr;
    std::string                          annotation_name;
};

/// Immutable snapshot of a lifted function's CFG — all the data needed for
/// visualization without the heavy LLVM Module or BinaryContext-owned annotations.
struct CfgSnapshot {
    std::set<lifter::edge_t>                          edges;
    std::set<lifter::lifted_bb_t>                     basic_blocks;
    std::map<lifter::bb_id_t, SyntheticBlockSnapshot> synthetic_blocks;
    uint64_t    entry_rva  = 0;
    std::string func_name;
};

/// Build a snapshot from a lift result. Copies the lightweight fields and any
/// BinaryContext-owned annotation names so the snapshot remains valid after the
/// BinaryContext is destroyed.
inline CfgSnapshot make_cfg_snapshot(const lifter::lift_result_t &lr,
                                     const BinaryContext& bctx,
                                     uint64_t     entry_rva,
                                     std::string  func_name = {})
{
    std::map<lifter::bb_id_t, SyntheticBlockSnapshot> synthetic_blocks;
    for (const auto &[id, synth] : lr.synthetic_blocks) {
        synthetic_blocks.emplace(id, SyntheticBlockSnapshot{
            .type = synth.type,
            .dest_addr = synth.dest_addr,
            .annotation_name = bctx.get_by_id(synth.annotation_id)->name,
        });
    }

    return {
        .edges            = lr.edges,
        .basic_blocks     = lr.basic_blocks,
        .synthetic_blocks = std::move(synthetic_blocks),
        .entry_rva        = entry_rva,
        .func_name        = std::move(func_name),
    };
}


inline const lifter::lifted_bb_t *find_real_block_containing_rva(const CfgSnapshot &cfg,
                                                            uint64_t           rva)
{
    using BBT = lifter::lifted_bb_t::Type;
    for (const auto &bb : cfg.basic_blocks) {
        if (bb.type != BBT::REAL || !bb.rva_range)
            continue;
        if (bb.rva_range->start() <= rva && rva < bb.rva_range->end())
            return &bb;
    }
    return nullptr;
}

inline std::optional<lifter::bb_id_t>
find_real_block_id_containing_rva(const CfgSnapshot &cfg, uint64_t rva)
{
    if (const auto *bb = find_real_block_containing_rva(cfg, rva))
        return bb->id;
    return std::nullopt;
}

inline std::optional<uint64_t>
find_real_block_start_containing_rva(const CfgSnapshot &cfg, uint64_t rva)
{
    if (const auto *bb = find_real_block_containing_rva(cfg, rva))
        return bb->rva_range->start();
    return std::nullopt;
}
} // namespace lifted::visualization
