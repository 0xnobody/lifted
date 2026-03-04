#pragma once

#include "verifier_state.hpp"
#include "paged_memory_state.hpp"
#include "../abi/calling_convention.hpp"

#include <cassert>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace lifted::verification
{
    // ── comparison_status ────────────────────────────────────────────────────

    enum class comparison_status
    {
        PASS,              // All compared dimensions match.
        FAIL_DIVERGED,     // At least one dimension diverges (valid comparison).
        FAIL_INCOMPARABLE, // Exit types are structurally incompatible — no
                           // meaningful comparison is possible.
        NEEDS_RERUN,       // One run terminated at a different checkpoint depth
                           // than the other, OR one run is CHECKPOINT_MISMATCH
                           // while the other is not (even at equal depth).
                           // Re-run the longer/non-mismatch executor with
                           //   verif_params.checkpoint_config.prev_record =
                           //       &shorter_run.checkpoint_record
                           // so both terminate at needs_rerun_at_index via
                           // CHECKPOINT_MISMATCH, then call compare_runs again.
    };

    // ── checkpoint_field ─────────────────────────────────────────────────────
    // Which component hash first diverged inside a checkpoint entry.
    //
    // combined_hash is intentionally NOT listed here — it is a derived value.
    // If combined_hash diverges but no sub-field does, that indicates a hash
    // computation bug; compare_runs asserts rather than surfacing it.

    enum class checkpoint_field
    {
        STATE,     // state_hash    (GPR/flag snapshots at BB and ext-call events)
        MEM_WRITE, // mem_write_hash
        READ,      // read_hash
        EXT_CALL,  // ext_call_hash
    };

    // ── checkpoint_divergence_t ───────────────────────────────────────────────

    struct checkpoint_divergence_t
    {
        size_t index;           // 1-based (matches checkpoint_record_t indexing)
        checkpoint_field field; // Which component hash first differs at index.
    };

    // ── dimension_results_t ──────────────────────────────────────────────────

    struct dimension_results_t
    {
        bool exit_type_match = false;
        bool checkpoint_match = false;
        bool reg_state_match = false;
        bool mem_snapshot_match = false;
        bool bb_trace_match = false;
        bool ext_calls_match = false;
    };

    // ── comparison_result_t ──────────────────────────────────────────────────

    struct comparison_result_t
    {
        comparison_status status = comparison_status::PASS;

        // Per-dimension verdicts.  Only populated when status is PASS or
        // FAIL_DIVERGED; all false for FAIL_INCOMPARABLE and NEEDS_RERUN.
        dimension_results_t dimensions;

        // Populated when status == NEEDS_RERUN.
        // Re-run the executor that ran further using the shorter run's
        // checkpoint_record as prev_record.  Both runs will then terminate at
        // the same CHECKPOINT_MISMATCH index and become directly comparable.
        std::optional<size_t> needs_rerun_at_index;

        // Populated when status == FAIL_DIVERGED and checkpoints diverge.
        // index is 1-based; field names which component hash first differs.
        // When the divergence is a length mismatch (different event counts),
        // index = min_event_count + 1 and field = STATE as a placeholder.
        std::optional<checkpoint_divergence_t> first_checkpoint_divergence;

        // Populated when status == FAIL_DIVERGED and BB trace diverges.
        // 0-based index into the normalized (fallthrough-stripped) trace.
        std::optional<size_t> first_trace_divergence;

        // Populated when status == FAIL_DIVERGED and ext call sequence diverges.
        // 0-based index into the ext_calls vector.
        std::optional<size_t> first_ext_call_divergence;

        // Print a human-readable summary of the comparison result.
        void print(std::ostream &os) const;
    };

    // ── compare_config_t ─────────────────────────────────────────────────────

    struct compare_config_t
    {
        // Optional ABI for register comparison.  If non-null, only ABI-relevant
        // registers are compared via get_divergent_registers().  If null, the 16
        // GPRs + rflags are compared via the same hash used by checkpoints,
        // avoiding false divergences from uninitialised padding/vector bytes.
        const abi::CallingConvention *abi = nullptr;
    };

    // ── compare_runs ─────────────────────────────────────────────────────────
    // Compare two run_result_t objects and return a structured verdict.
    //
    // Classification precedence (checked in order):
    //   1. FAIL_INCOMPARABLE — either run ended in a fault condition whose
    //      synchronisation with the other executor is not guaranteed.
    //   2. NEEDS_RERUN — checkpoint depths differ; re-run needed before a
    //      meaningful final-state comparison is possible.
    //   3. PASS / FAIL_DIVERGED — all six dimensions compared.
    comparison_result_t compare_runs(
        const run_result_t &r1,
        const run_result_t &r2,
        const compare_config_t &cfg = {});

    // ═════════════════════════════════════════════════════════════════════════
    // Detailed diff system
    // ─────────────────────────────────────────────────────────────────────────
    // diff_runs() is only valid when compare_runs() returned FAIL_DIVERGED.
    // It enumerates *all* divergences across every dimension in machine-
    // parseable structures.  Call compare_runs first to classify the pair;
    // call diff_runs after to obtain the full detail.
    // ═════════════════════════════════════════════════════════════════════════

    // ── reg_diff_t ────────────────────────────────────────────────────────────
    // One entry per GPR / flag that diverges between the two final states.

    struct reg_diff_entry_t
    {
        std::string name; // e.g. "rax", "rflag"
        uint64_t val_r1;
        uint64_t val_r2;
    };

    struct reg_diff_t
    {
        std::vector<reg_diff_entry_t> divergent; // non-empty iff registers differ
    };

    // ── bb_trace_diff_t ───────────────────────────────────────────────────────
    // Positional diff of the two BB address traces.
    // An entry is emitted for every index where the traces disagree, including
    // positions beyond the end of the shorter trace (represented as nullopt).

    struct bb_trace_diff_entry_t
    {
        size_t index;                   // 0-based into bb_trace
        std::optional<uint64_t> rva_r1; // nullopt if r1 trace ended before index
        std::optional<uint64_t> rva_r2; // nullopt if r2 trace ended before index
    };

    struct bb_trace_diff_t
    {
        size_t len_r1;
        size_t len_r2;
        std::vector<bb_trace_diff_entry_t> entries; // all diverging positions
    };

    // ── ext_call_diff_t ───────────────────────────────────────────────────────
    // Positional diff of the external-call address sequences.

    struct ext_call_diff_entry_t
    {
        size_t index;                    // 0-based into ext_calls
        std::optional<uint64_t> addr_r1; // nullopt if sequence ended before index
        std::optional<uint64_t> addr_r2; // nullopt if sequence ended before index
    };

    struct ext_call_diff_t
    {
        size_t len_r1;
        size_t len_r2;
        std::vector<ext_call_diff_entry_t> entries; // all diverging positions
    };

    // ── checkpoint_diff_t ─────────────────────────────────────────────────────
    // All checkpoint entries where combined_hash differs.
    // The raw checkpoint_t values for both sides are included so downstream
    // tools can inspect individual sub-hashes (state_hash, mem_write_hash, …).
    // For length-only divergences (one record is shorter), the entry at
    // index == min(len_r1, len_r2) + 1 has a zero-valued checkpoint_t on the
    // shorter side (sentinel) — first_diverging_field is STATE as a placeholder.

    struct checkpoint_diff_entry_t
    {
        size_t index; // 1-based (matches checkpoint_record_t indexing)
        checkpoint_field first_diverging_field;
        checkpoint_t cp_r1; // raw checkpoint_t at this index on r1's side
        checkpoint_t cp_r2; // raw checkpoint_t at this index on r2's side

        // Up to kBBContext BBs ending at-or-before the diverging event, in
        // execution order.  Drawn from r1's bb_trace (r2 is identical up to
        // this point because all preceding checkpoints matched).
        std::vector<uint64_t> preceding_bbs;
        // True when the diverging event itself is a BB entry (field == STATE
        // and the checkpoint was produced by push_bb, not push_ext_call).
        // In that case the last entry of preceding_bbs IS the diverging BB.
        bool diverging_event_is_bb = false;
    };

    struct checkpoint_diff_t
    {
        size_t len_r1;                                // event_count() for r1
        size_t len_r2;                                // event_count() for r2
        std::vector<checkpoint_diff_entry_t> entries; // all diverging indices
    };

    // ── diff_result_t ─────────────────────────────────────────────────────────
    // Top-level output of diff_runs().
    //
    // Each optional field is set iff that dimension diverged.  A nullopt means
    // the dimension was identical (or not applicable given recording flags).
    // All present fields are fully populated — not just the first divergence.

    struct diff_result_t
    {
        // Set iff the two exit types differ.
        std::optional<std::pair<exit_type, exit_type>> exit_type_diff;

        // Set iff at least one GPR / flag diverges in the final states.
        std::optional<reg_diff_t> reg_diff;

        // Set iff written memory differs.  Reuses the rich memory_diff_result_t
        // from paged_memory_state.hpp (page_diff_t with bitsets + byte ranges).
        std::optional<memory_diff_result_t> mem_diff;

        // Set iff the BB execution traces differ at any position.
        std::optional<bb_trace_diff_t> bb_trace_diff;

        // Set iff the external-call sequences differ at any position.
        std::optional<ext_call_diff_t> ext_call_diff;

        // Set iff any checkpoint entry's combined_hash differs.
        std::optional<checkpoint_diff_t> checkpoint_diff;

        // Print a human-readable representation of all divergences.
        void print(std::ostream &os) const;
    };

    // ── diff_runs ─────────────────────────────────────────────────────────────
    // Produce a detailed, machine-parseable diff between two FAIL_DIVERGED runs.
    //
    // Precondition: compare_runs(r1, r2) returned FAIL_DIVERGED.
    //   Calling this on any other status is a logic error and will assert.
    //
    // cfg must be the same compare_config_t used to obtain the comparison_result_t
    // (it governs which registers are examined).
    diff_result_t diff_runs(
        const run_result_t &r1,
        const run_result_t &r2,
        const compare_config_t &cfg = {});

} // namespace lifted::verification
