#pragma once

#include "verifier_state.hpp"
#include "../abi/calling_convention.hpp"

#include <cassert>
#include <iosfwd>
#include <optional>

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
                           // than the other.  Re-run the longer executor with
                           //   verif_params.checkpoint_config.prev_record =
                           //       &shorter_run.checkpoint_record
                           // so both terminate at needs_rerun_at_index, then
                           // call compare_runs again.
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

} // namespace lifted::verification
