#pragma once

#include "lifter_types.hpp"
#include "../binary_context.hpp"

#include <deque>
#include <map>
#include <set>
#include <utility>

namespace lifted::lifter
{

/// Per-lift()-call mutable state.  A fresh instance is created at the start of
/// each Lifter::lift() call so that multiple calls on the same Lifter don't
/// bleed state into each other.
///
/// Lifter-level state (explored_ cache, callee stubs, synthetic ID counter)
/// lives on the Lifter itself and is shared across calls.
struct lift_context_t
{
    // ── Work queues ───────────────────────────────────────────────────────

    std::deque<bb_id_t> worklist; ///< Blocks to lift for the first time.
    std::set<bb_id_t>   reprove;  ///< Blocks to re-run resolve_targets on.

    // ── CFG state ─────────────────────────────────────────────────────────

    std::set<edge_t>                          edges;
    std::map<bb_id_t, synthetic_block_info_t> synthetic_blocks;

    // ── Dedup indices (prevent duplicate synthetics on reprove) ───────────

    /// (source_bb_id, dest_addr) → synthetic block ID for EXTERNAL edges.
    std::map<std::pair<bb_id_t, uint64_t>, bb_id_t> external_synthetic_index;

    /// source_bb_id → synthetic block ID for INDIRECT edges.
    /// A BB can have at most one indirect outgoing edge.
    std::map<bb_id_t, bb_id_t> indirect_synthetic_index;

    /// source_bb_id → synthetic block ID for RECURSIVE edges.
    /// A BB can have at most one direct self-recursive outgoing edge.
    std::map<bb_id_t, bb_id_t> recursive_synthetic_index;

    // ── Return-edge cross-reference tables ──────────────────────────────────

    /// Blocks that resolved to RETURN_TO_CALLER (e.g. `ret`-terminated).
    /// stitch_cfg uses this to default their synthetic dispatch to the natural
    /// function return when no continuation block is known.
    std::set<bb_id_t> return_to_caller_blocks;
    // ── Entry-point metadata ───────────────────────────────────────────────
    uint64_t entry_rva = 0;
    annotation_id_t entry_annotation_id = INVALID_ANNOTATION_ID;
    // ── Helpers ───────────────────────────────────────────────────────────

    /// When block splitting redirects all original successors to `new_source`,
    /// the per-source synthetic dedup indices must follow the same ownership so
    /// later reprove of `new_source` reuses the existing synthetic blocks.
    void remap_synthetic_sources(bb_id_t old_source, bb_id_t new_source)
    {
        if (old_source == new_source)
            return;

        for (auto it = external_synthetic_index.begin();
             it != external_synthetic_index.end(); )
        {
            if (it->first.first != old_source)
            {
                ++it;
                continue;
            }

            const auto dest_addr = it->first.second;
            const auto synth_id = it->second;
            it = external_synthetic_index.erase(it);
            external_synthetic_index.emplace(
                std::make_pair(new_source, dest_addr), synth_id);
        }

        auto remap_single_source_index = [old_source, new_source](auto &index)
        {
            auto it = index.find(old_source);
            if (it == index.end())
                return;

            const auto synth_id = it->second;
            index.erase(it);
            index.emplace(new_source, synth_id);
        };

        remap_single_source_index(indirect_synthetic_index);
        remap_single_source_index(recursive_synthetic_index);
    }

    /// Returns true when any edge exists between src and dst (ignoring type).
    bool has_edge_between(bb_id_t src, bb_id_t dst) const
    {
        for (const auto &e : edges)
            if (e.source == src && e.dest == dst)
                return true;
        return false;
    }

    /// BFS from `root` over successor edges, inserting every reachable block
    /// (including root) into reprove.  Called whenever a new predecessor edge
    /// is added to an already-explored block.
    void reprove_subtree(bb_id_t root)
    {
        std::set<bb_id_t>    visited;
        std::vector<bb_id_t> stack = {root};
        while (!stack.empty())
        {
            bb_id_t curr = stack.back();
            stack.pop_back();
            if (!visited.insert(curr).second)
                continue;
            reprove.insert(curr);
            for (const auto &e : edges)
                if (e.source == curr && !visited.count(e.dest))
                    stack.push_back(e.dest);
        }
    }
};

} // namespace lifted::lifter
