#pragma once

#include "verifier_context.hpp" // State
#include "event_flags.hpp"

#include "../hash_mix.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Checkpoint system: track execution traces and compare runs for divergence.
//
// Three-layer design:
//
//   checkpoint_t          — a single immutable snapshot of running digests
//   checkpoint_record_t   — owns the checkpoints vector; all hash logic lives here
//   checkpoint_config_t   — passive configuration (sync_on + compare_dims + prev_record)
//
// The caller (e.g. verifier_state) decides which events become checkpoints via
// checkpoint_config_t::sync_on. Each push samples the currently enabled semantic
// digests into checkpoint_t, returns the combined hash for the configured compare
// dimensions, and leaves any live comparison / early-abort policy to the caller.

namespace lifted::verification
{
    // ── checkpoint_detail_t ───────────────────────────────────────────────────
    //
    // Parallel to checkpoint_t: one record per push_* call, written only when
    // checkpoint_record_t::record_details == true. Stores the raw event data so
    // deep-dive can reconstruct a side-by-side chronological trace.

    struct checkpoint_detail_t
    {
        enum class kind : uint8_t { BB, MEM_READ, MEM_WRITE, EXT_CALL };

        kind     type  = kind::BB;
        uint64_t addr  = 0; // BB RVA | mem address | ext_call target
        uint64_t value = 0; // mem read/write value; 0 for BB/EXT_CALL
        uint32_t size  = 0; // mem byte width (1/2/4/8); 0 for BB/EXT_CALL

        // Full remill register file at this event.
        // Set for BB and EXT_CALL (State* available); nullopt for mem ops.
        std::optional<State> state;
    };

    // ── checkpoint_t ─────────────────────────────────────────────────────────
    //
    // One immutable snapshot appended on every synchronized event. All hashes are
    // running: each push copies the previous checkpoint_t, updates the relevant
    // components, recomputes combined_hash for the record's configured
    // compare_dimension_flags, then appends the new snapshot.

    struct checkpoint_t
    {
        uint64_t state_hash = 0;           // Running hash of checkpoint-time register state (BB + ext-call events).
        uint64_t bb_trace_hash = 0;        // Running hash of BB-entry RVAs.
        uint64_t mem_write_hash = 0;       // Running hash of exact write sequence (addr, value, size).
        uint64_t memory_contents_hash = 0; // Running hash of current written-byte contents (order/width insensitive).
        uint64_t read_hash = 0;            // Running hash of exact read sequence (addr, value, size).
        uint64_t ext_call_hash = 0;        // Running hash of external-call targets.
        uint64_t combined_hash = 0;        // Mix of enabled component hashes + checkpoint index.
    };

    // ── checkpoint_record_t ───────────────────────────────────────────────────
    //
    // Owns the checkpoint vector. All hash logic lives here.
    //
    // checkpoints[0] is an all-zero sentinel so every push has a valid previous
    // entry to copy-and-mix from. event_count() excludes it.

    struct checkpoint_record_t
    {
        std::vector<checkpoint_t> checkpoints;

        // Parallel to checkpoints: bb_counts[i] is the number of push_bb calls
        // that have occurred in events 1..i (sentinel at [0] = 0). Kept separate
        // so checkpoint_t stays a plain value type. Used post-hoc to map a
        // checkpoint event index back to a bb_trace position for diff display.
        std::vector<uint32_t> bb_counts;

        // Per-kind event counts. Used to decide when zero-valued hashes are genuine
        // evidence of an empty trace versus merely the absence of synchronized events.
        uint32_t mem_write_count = 0;
        uint32_t read_count = 0;
        uint32_t ext_call_count = 0;

        // Which event types produced checkpoint entries for this record.
        event_flags sync_on = event_flags::NONE;

        // Which semantic dimensions were mixed into combined_hash during the run.
        // Raw component hashes are still retained in checkpoint_t regardless of
        // this policy so post-run comparison can choose a narrower/wider subset.
        compare_dimension_flags compare_dims = compare_dimension_flags::DEFAULT;

        // ── Detail recording (opt-in) ─────────────────────────────────────────
        // When record_details == true, every push_* call also appends to details[].
        // details[i] is parallel to checkpoints[i] (same 1-based indexing;
        // details[0] is a default-constructed sentinel matching checkpoints[0]).
        bool                             record_details = false;
        std::vector<checkpoint_detail_t> details;

        void enable_details() noexcept
        {
            assert(checkpoints.size() == 1 && details.empty() &&
                   "enable_details() must be called before any push");
            record_details = true;
            details.push_back({}); // sentinel at [0]
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

        // Compose the checkpoint's comparison hash for a given dimension policy.
        static uint64_t compose_combined_hash(const checkpoint_t &cp,
                                              size_t index,
                                              compare_dimension_flags dims) noexcept;

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
        // Each method copies the last checkpoint_t, updates the relevant running
        // digests, snapshots the current memory-contents hash, recomputes
        // combined_hash using compare_dims, appends the new entry, and returns the
        // new combined_hash.

        uint64_t push_bb(uint64_t rva, const State *s, uint64_t memory_contents_hash);
        uint64_t push_write(uint64_t addr, uint64_t value, uint32_t size, uint64_t memory_contents_hash);
        uint64_t push_read(uint64_t addr, uint64_t value, uint32_t size, uint64_t memory_contents_hash);
        uint64_t push_ext_call(uint64_t addr, const State *s, uint64_t memory_contents_hash);
    };

    // ── checkpoint_config_t ───────────────────────────────────────────────────
    //
    // Pure passive configuration. No methods, no event handling, no state
    // mutation. The caller reads these fields and decides what to do.
    //
    //   sync_on      — which event types append checkpoint entries
    //   compare_dims — which semantic dimensions are mixed into combined_hash
    //   prev_record  — if non-null, comparison mode is active; the caller
    //                  compares push_* return values against
    //                  prev_record->checkpoints[idx].combined_hash

    struct checkpoint_config_t
    {
        event_flags sync_on = event_flags::DEFAULT;
        compare_dimension_flags compare_dims = compare_dimension_flags::DEFAULT;
        const checkpoint_record_t *prev_record = nullptr;
        // When true, each push_* call also appends a checkpoint_detail_t to
        // checkpoint_record_t::details (in addition to the normal hash update).
        // Off by default to avoid any overhead in non-debug pipeline runs.
        bool record_details = false;
    };

} // namespace lifted::verification
