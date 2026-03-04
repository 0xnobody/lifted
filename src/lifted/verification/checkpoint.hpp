#pragma once

#include "verifier_context.hpp" // State
#include "event_flags.hpp"

#include "../hash_mix.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <optional>

// Checkpoint system: track execution traces and compare runs for divergence.
//
// Three-layer design:
//
//   checkpoint_t          — a single immutable snapshot (trivially copyable, ~40 B)
//   checkpoint_record_t   — owns the checkpoints vector; all hash logic lives here
//   checkpoint_config_t   — pure passive config (record_on + optional prev_record pointer)
//
// The caller (e.g. a verifier_state subclass) reads config.record_on to decide
// whether to push an event, calls the relevant push_* method, receives the new
// combined_hash, and may compare it against
// config.prev_record->checkpoints[idx].combined_hash as it sees fit.
//
// No gating, live comparison, or early-abort logic lives in this file.

namespace lifted::verification
{
    // ── checkpoint_detail_t ───────────────────────────────────────────────────
    //
    // Parallel to checkpoint_t: one record per push_* call, written only when
    // checkpoint_record_t::record_details == true.  Stores the raw event data
    // so the deep-dive display can reconstruct a side-by-side event trace.
    //
    //   BB / EXT_CALL events: addr = RVA or call target; state = full register file.
    //   MEM_READ / MEM_WRITE: addr = memory address; value = transferred value;
    //                         size = byte width (1/2/4/8); state = nullopt.

    struct checkpoint_detail_t
    {
        enum class kind : uint8_t { BB, MEM_READ, MEM_WRITE, EXT_CALL };

        kind     type  = kind::BB;
        uint64_t addr  = 0;   // BB RVA | mem address | ext_call target
        uint64_t value = 0;   // mem read/write value; 0 for BB/EXT_CALL
        uint32_t size  = 0;   // mem byte width (1/2/4/8); 0 for BB/EXT_CALL

        // Full remill register file at this event.
        // Set for BB and EXT_CALL (State* available); nullopt for mem ops.
        // Storing the full State enables future XMM/segment-register diffs
        // without any API change.
        std::optional<State> state;
    };

    // ── checkpoint_t ─────────────────────────────────────────────────────────
    //
    // One immutable snapshot appended on every push.  All five hashes are
    // *running* — each push copies the previous entry and mixes new data in,
    // so every checkpoint encodes the full history up to that point.
    struct checkpoint_t
    {
        uint64_t state_hash = 0;     // Running hash of GPR/flag state (BB + ext-call events).
        uint64_t mem_write_hash = 0; // Running hash of (addr, value, size) for writes.
        uint64_t read_hash = 0;      // Running hash of (addr, value, size) for reads.
        uint64_t ext_call_hash = 0;  // Running hash of (addr, state) for external calls.
        uint64_t combined_hash = 0;  // Mix of all four component hashes + event index.
    };

    // ── checkpoint_record_t ───────────────────────────────────────────────────
    //
    // Owns the checkpoint vector.  All hash logic lives here.
    //
    // checkpoints[0] is an all-zero sentinel so every push has a valid
    // "previous" entry to copy-and-mix from.  event_count() excludes it.

    struct checkpoint_record_t
    {
        std::vector<checkpoint_t> checkpoints;

        // Parallel to checkpoints: bb_counts[i] is the number of push_bb calls
        // that have occurred in events 1..i (sentinel at [0] = 0).  Kept separate
        // so checkpoint_t stays a plain 40-byte value type.  Used post-hoc to map
        // a checkpoint event index back to a bb_trace position for diff display.
        std::vector<uint32_t> bb_counts;

        // Which event types were recorded into this record.  Set by the
        // verifier_state from checkpoint_config_t::record_on at construction time
        // and preserved into run_result_t::checkpoint_record.  The comparator
        // uses this to determine which sub-hash shortcuts are sound: a shortcut
        // for dimension X is only valid when X's flag is set in BOTH records,
        // otherwise the sub-hash is zero-filled and cannot distinguish
        // "no events occurred" from "events were not recorded".
        event_flags record_on = event_flags::NONE;

        // ── Detail recording (opt-in) ─────────────────────────────────────────
        // When record_details == true, every push_* call also appends to details[].
        // details[i] is parallel to checkpoints[i] (same 1-based indexing;
        // details[0] is a default-constructed sentinel matching checkpoints[0]).
        //
        // Invariant: record_details == true  →  details.size() == checkpoints.size()
        //            record_details == false →  details.empty()
        bool                             record_details = false;
        std::vector<checkpoint_detail_t> details;

        // Call before any push_* to activate detail recording.
        // Asserts that no pushes have happened yet, then pushes the sentinel at [0].
        void enable_details() noexcept
        {
            assert(checkpoints.size() == 1 && details.empty() &&
                   "enable_details() must be called before any push");
            record_details = true;
            details.push_back({});   // sentinel at [0]
        }

        checkpoint_record_t()
        {
            checkpoints.push_back({}); // sentinel
            bb_counts.push_back(0);    // sentinel: 0 BBs before event 0
        }

        // ── State hashing ─────────────────────────────────────────────────────

        // Hash the observable integer register + flags state of s.
        // Hashes only the 16 named GPRs + rflag.flat — avoids padding/uninitialised
        // bytes in vector/segment registers that would cause false divergence.
        static uint64_t hash_state(const State *s) noexcept;

        // ── Accessors ─────────────────────────────────────────────────────────

        uint64_t final_hash() const noexcept
        {
            return checkpoints.back().combined_hash;
        }

        size_t event_count() const noexcept
        {
            return checkpoints.size() - 1; // exclude sentinel
        }

        bool operator==(const checkpoint_record_t &o) const noexcept
        {
            return event_count() == o.event_count() && final_hash() == o.final_hash();
        }

        bool operator!=(const checkpoint_record_t &o) const noexcept
        {
            return !(*this == o);
        }

        // ── Push methods ──────────────────────────────────────────────────────
        //
        // Each method copies the last checkpoint_t, mixes new data into the
        // relevant component hash, recomputes combined_hash, pushes the result,
        // and returns the new combined_hash.

        uint64_t push_bb(uint64_t rva, const State *s);
        uint64_t push_write(uint64_t addr, uint64_t value, uint32_t size);
        uint64_t push_read(uint64_t addr, uint64_t value, uint32_t size);
        uint64_t push_ext_call(uint64_t addr, const State *s);

    private:
        static uint64_t make_combined(const checkpoint_t &cp, size_t index) noexcept
        {
            return hash::mix_many(cp.state_hash,
                                  cp.mem_write_hash,
                                  cp.read_hash,
                                  cp.ext_call_hash,
                                  static_cast<uint64_t>(index));
        }
    };

    // ── checkpoint_config_t ───────────────────────────────────────────────────
    //
    // Pure passive configuration.  No methods, no event handling, no state
    // mutation.  The caller reads these fields and decides what to do.
    //
    //   record_on   — which event types to record
    //   prev_record — if non-null, comparison mode is active; the caller
    //                 compares push_* return values against
    //                 prev_record->checkpoints[idx].combined_hash

    struct checkpoint_config_t
    {
        event_flags record_on = event_flags::DEFAULT;
        const checkpoint_record_t *prev_record = nullptr;
        // When true, each push_* call also appends a checkpoint_detail_t to
        // checkpoint_record_t::details (in addition to the normal hash update).
        // Off by default to avoid any overhead in non-debug pipeline runs.
        bool record_details = false;
    };

} // namespace lifted::verification
