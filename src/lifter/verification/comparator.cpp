#include "comparator.hpp"
#include "checkpoint.hpp"

#include <algorithm>
#include <cassert>
#include <ostream>
#include <vector>

namespace lifted::verification
{
    // ── Internal helpers ─────────────────────────────────────────────────────

    // Returns true for exit types where executor synchronisation is not
    // guaranteed.  Change this predicate to enable Fault×Fault comparisons.
    static bool is_fault(exit_type e) noexcept
    {
        return e == exit_type::EXCEPTION || e == exit_type::MISSING_BLOCK;
    }

    // Effective checkpoint depth of a run: how far into the event stream it got.
    // For CHECKPOINT_MISMATCH, this is the index of the mismatching slot
    // (failed_checkpoint_idx).  For all other exits, it is the total event count.
    static size_t checkpoint_depth(const run_result_t &r) noexcept
    {
        if (r.exit_reason == exit_type::CHECKPOINT_MISMATCH)
            return r.failed_checkpoint_idx.value_or(0);
        return r.checkpoint_record.event_count();
    }

    // ── Per-dimension comparison helpers ─────────────────────────────────────

    static bool cmp_exit_types(const run_result_t &r1, const run_result_t &r2)
    {
        return r1.exit_reason == r2.exit_reason;
    }

    static bool cmp_checkpoints(
        const run_result_t &r1,
        const run_result_t &r2,
        std::optional<checkpoint_divergence_t> &out_divergence)
    {
        const auto &cp1 = r1.checkpoint_record.checkpoints;
        const auto &cp2 = r2.checkpoint_record.checkpoints;

        // Skip sentinel at index 0; real events start at 1.
        size_t common = std::min(cp1.size(), cp2.size());
        for (size_t i = 1; i < common; ++i)
        {
            if (cp1[i].combined_hash == cp2[i].combined_hash)
                continue;

            // Narrow to which sub-field first diverges at this index.
            checkpoint_field field;
            if (cp1[i].state_hash != cp2[i].state_hash)
                field = checkpoint_field::STATE;
            else if (cp1[i].mem_write_hash != cp2[i].mem_write_hash)
                field = checkpoint_field::MEM_WRITE;
            else if (cp1[i].read_hash != cp2[i].read_hash)
                field = checkpoint_field::READ;
            else if (cp1[i].ext_call_hash != cp2[i].ext_call_hash)
                field = checkpoint_field::EXT_CALL;
            else
            {
                assert(false &&
                       "combined_hash diverged but no sub-field differs — hash computation bug");
                field = checkpoint_field::STATE; // unreachable; suppress warning
            }

            out_divergence = checkpoint_divergence_t{i, field};
            return false;
        }

        // If shared prefix matches but lengths differ, that is itself a divergence.
        // field = STATE is a placeholder; the meaningful information is the index.
        if (cp1.size() != cp2.size())
        {
            out_divergence = checkpoint_divergence_t{common, checkpoint_field::STATE};
            return false;
        }

        return true;
    }

    static bool cmp_reg_states(
        const run_result_t &r1,
        const run_result_t &r2,
        const compare_config_t &cfg)
    {
        if (cfg.abi)
        {
            auto diffs = cfg.abi->get_divergent_registers(r1.final_state, r2.final_state);
            return diffs.empty();
        }
        // No ABI: compare via the same running hash used by checkpoints (16 GPRs
        // + rflags).  This avoids false divergences from uninitialised padding or
        // vector-register bytes that neither executor initialises meaningfully.
        return checkpoint_record_t::hash_state(&r1.final_state) ==
               checkpoint_record_t::hash_state(&r2.final_state);
    }

    static bool cmp_mem_snapshots(const run_result_t &r1, const run_result_t &r2)
    {
        return r1.mem_snapshot.compare(r2.mem_snapshot);
    }

    static bool cmp_bb_traces(
        const run_result_t &r1,
        const run_result_t &r2,
        std::optional<size_t> &out_divergence)
    {
        const auto &t1 = r1.bb_trace;
        const auto &t2 = r2.bb_trace;

        size_t common = std::min(t1.size(), t2.size());
        for (size_t i = 0; i < common; ++i)
        {
            if (t1[i] != t2[i])
            {
                out_divergence = i;
                return false;
            }
        }
        if (t1.size() != t2.size())
        {
            out_divergence = common;
            return false;
        }
        return true;
    }

    static bool cmp_ext_calls(
        const run_result_t &r1,
        const run_result_t &r2,
        std::optional<size_t> &out_divergence)
    {
        size_t common = std::min(r1.ext_calls.size(), r2.ext_calls.size());
        for (size_t i = 0; i < common; ++i)
        {
            if (r1.ext_calls[i] != r2.ext_calls[i])
            {
                out_divergence = i;
                return false;
            }
        }
        if (r1.ext_calls.size() != r2.ext_calls.size())
        {
            out_divergence = common;
            return false;
        }
        return true;
    }

    // ── comparison_result_t::print ────────────────────────────────────────────

    static const char *status_str(comparison_status s) noexcept
    {
        switch (s)
        {
        case comparison_status::PASS:
            return "PASS";
        case comparison_status::FAIL_DIVERGED:
            return "FAIL_DIVERGED";
        case comparison_status::FAIL_INCOMPARABLE:
            return "FAIL_INCOMPARABLE";
        case comparison_status::NEEDS_RERUN:
            return "NEEDS_RERUN";
        }
        return "UNKNOWN";
    }

    static const char *field_str(checkpoint_field f) noexcept
    {
        switch (f)
        {
        case checkpoint_field::STATE:
            return "state";
        case checkpoint_field::MEM_WRITE:
            return "mem_write";
        case checkpoint_field::READ:
            return "read";
        case checkpoint_field::EXT_CALL:
            return "ext_call";
        }
        return "unknown";
    }

    void comparison_result_t::print(std::ostream &os) const
    {
        os << "[CMP] " << status_str(status);

        if (status == comparison_status::NEEDS_RERUN)
        {
            os << " at checkpoint " << *needs_rerun_at_index << "\n";
            return;
        }

        if (status == comparison_status::FAIL_DIVERGED)
        {
            os << " exit=" << dimensions.exit_type_match
               << " chk=" << dimensions.checkpoint_match
               << " reg=" << dimensions.reg_state_match
               << " mem=" << dimensions.mem_snapshot_match
               << " bb=" << dimensions.bb_trace_match
               << " ext=" << dimensions.ext_calls_match;
        }

        os << "\n";

        if (first_checkpoint_divergence)
            os << "  checkpoint diverges at index "
               << first_checkpoint_divergence->index
               << " (field: " << field_str(first_checkpoint_divergence->field) << ")\n";
        if (first_trace_divergence)
            os << "  BB trace diverges at index " << *first_trace_divergence << "\n";
        if (first_ext_call_divergence)
            os << "  ext call diverges at index " << *first_ext_call_divergence << "\n";
    }

    // ── compare_runs ─────────────────────────────────────────────────────────

    comparison_result_t compare_runs(
        const run_result_t &r1,
        const run_result_t &r2,
        const compare_config_t &cfg)
    {
        comparison_result_t result;

        // ── Phase 1: FAIL_INCOMPARABLE ────────────────────────────────────────
        // Any fault exit makes the pair incomparable in the current
        // implementation; synchronisation between executors at fault sites is
        // not guaranteed.  To relax this (e.g. allow EXCEPTION×EXCEPTION),
        // adjust is_fault() above.
        if (is_fault(r1.exit_reason) || is_fault(r2.exit_reason))
        {
            result.status = comparison_status::FAIL_INCOMPARABLE;
            return result;
        }

        // ── Phase 2: NEEDS_RERUN ──────────────────────────────────────────────
        // Both runs are clean exits here.  If at least one stopped via
        // CHECKPOINT_MISMATCH and the two checkpoint depths differ, the final
        // states are at different program points — a direct comparison is
        // meaningless.  The call site must re-run the deeper executor with
        //   verif_params.checkpoint_config.prev_record = &shallower.checkpoint_record
        // so both terminate at the same index (CHECKPOINT_MISMATCH), then call
        // compare_runs again.
        {
            size_t d1 = checkpoint_depth(r1);
            size_t d2 = checkpoint_depth(r2);
            bool either_mismatch = r1.exit_reason == exit_type::CHECKPOINT_MISMATCH ||
                                   r2.exit_reason == exit_type::CHECKPOINT_MISMATCH;
            if (either_mismatch && d1 != d2)
            {
                result.status = comparison_status::NEEDS_RERUN;
                result.needs_rerun_at_index = std::min(d1, d2);
                return result;
            }
        }

        // ── Phase 3: Per-dimension comparison ────────────────────────────────
        //
        // For each dimension, use the corresponding checkpoint sub-hash as a
        // fast-path when:
        //   (a) the flag for that event type is set in BOTH records, and
        //   (b) the final sub-hash values agree.
        //
        // If a flag is absent in either record, the sub-hash stayed zero
        // throughout — zero==zero cannot distinguish "no events" from "not
        // recorded", so we fall through to full run_result_t comparison.
        //
        // Sub-hash → event and isolation (from checkpoint.cpp):
        //   state_hash     ← push_bb only      → encodes (rva, state) per BB
        //   mem_write_hash ← push_write only    → encodes (addr, value, size) per write
        //   read_hash      ← push_read only     → encodes (addr, value, size) per read
        //   ext_call_hash  ← push_ext_call only → encodes (addr, state) per ext call
        //
        // reg_state_match has NO shortcut: state_hash captures state at BB
        // ENTRY, not after the last instruction — the final register state is
        // not encoded in any checkpoint sub-hash.

        const auto common_flags =
            r1.checkpoint_record.flags & r2.checkpoint_record.flags;

        // Final checkpoint entry (sentinel always at [0]; real data at back()).
        const checkpoint_t &cf1 = r1.checkpoint_record.checkpoints.back();
        const checkpoint_t &cf2 = r2.checkpoint_record.checkpoints.back();

        bool all_match = true;

        // ── exit_type: always explicit ────────────────────────────────────────
        result.dimensions.exit_type_match = cmp_exit_types(r1, r2);
        all_match &= result.dimensions.exit_type_match;

        // ── checkpoint_match ──────────────────────────────────────────────────
        // If event counts and final combined_hash agree, all intermediate
        // entries agree too (by construction of the running hash).  Skip walk.
        {
            size_t n1 = r1.checkpoint_record.event_count();
            size_t n2 = r2.checkpoint_record.event_count();
            if (n1 > 0 && n1 == n2 && cf1.combined_hash == cf2.combined_hash)
                result.dimensions.checkpoint_match = true;
            else
                result.dimensions.checkpoint_match =
                    cmp_checkpoints(r1, r2, result.first_checkpoint_divergence);
        }
        all_match &= result.dimensions.checkpoint_match;

        // ── bb_trace_match ────────────────────────────────────────────────────
        // state_hash is exclusively accumulated by push_bb; matching final
        // state_hash implies an identical (rva, state) sequence at every BB
        // entry, which implies an identical bb_trace vector.
        if (has_flag(common_flags, record_on_flags::BB) &&
            cf1.state_hash == cf2.state_hash)
            result.dimensions.bb_trace_match = true;
        else
            result.dimensions.bb_trace_match =
                cmp_bb_traces(r1, r2, result.first_trace_divergence);
        all_match &= result.dimensions.bb_trace_match;

        // ── ext_calls_match ───────────────────────────────────────────────────
        // ext_call_hash is exclusively accumulated by push_ext_call; matching
        // final hash implies an identical external-call address sequence.
        if (has_flag(common_flags, record_on_flags::EXT_CALL) &&
            cf1.ext_call_hash == cf2.ext_call_hash)
            result.dimensions.ext_calls_match = true;
        else
            result.dimensions.ext_calls_match =
                cmp_ext_calls(r1, r2, result.first_ext_call_divergence);
        all_match &= result.dimensions.ext_calls_match;

        // ── mem_snapshot_match ────────────────────────────────────────────────
        // mem_write_hash encodes the full write sequence (addr, value, size).
        // Matching hashes imply identical writes → identical written memory.
        // MEM_READ is not required: if oracle reads diverged, any effect on
        // computation would propagate into the write sequence and cause
        // mem_write_hash to diverge first.
        if (has_flag(common_flags, record_on_flags::MEM_WRITE) &&
            cf1.mem_write_hash == cf2.mem_write_hash)
            result.dimensions.mem_snapshot_match = true;
        else
            result.dimensions.mem_snapshot_match = cmp_mem_snapshots(r1, r2);
        all_match &= result.dimensions.mem_snapshot_match;

        // ── reg_state_match ───────────────────────────────────────────────────
        // Final register state is captured after the last instruction executes.
        // state_hash only records state at BB ENTRY — no shortcut is available.
        result.dimensions.reg_state_match = cmp_reg_states(r1, r2, cfg);
        all_match &= result.dimensions.reg_state_match;

        result.status = all_match ? comparison_status::PASS
                                  : comparison_status::FAIL_DIVERGED;
        return result;
    }

} // namespace lifted::verification
