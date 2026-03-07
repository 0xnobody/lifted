#pragma once

#include "lifter_types.hpp"

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


    // ── Return-edge cross-reference tables ──────────────────────────────────

    /// Blocks that resolved to RETURN_TO_CALLER (e.g. `ret`-terminated).
    /// When a new return_continuation_site is discovered, RETURN_CONTINUATION
    /// edges are retroactively added from every block in this set.
    std::set<bb_id_t> return_to_caller_blocks;

    /// Return sites of intra-function call instructions (e.g. self-recursion).
    /// When a RETURN_TO_CALLER block is first processed, RETURN_CONTINUATION
    /// edges are added from it to every site already in this set.
    std::set<bb_id_t> return_continuation_sites;
    // ── Entry point (for resolve_context_t) ──────────────────────────────

    uint64_t entry_rva = 0;

    // ── Helpers ───────────────────────────────────────────────────────────

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
                // RETURN_CONTINUATION edges connect ret-blocks to return sites;
                // the return sites' backward slices are unaffected by who can
                // ret to them, so skip them here to avoid pointless reproving.
                if (e.source == curr && !visited.count(e.dest) &&
                    e.type != edge_t::Type::RETURN_CONTINUATION)
                    stack.push_back(e.dest);
        }
    }
};

} // namespace lifted::lifter
