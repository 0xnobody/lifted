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
        // The final states of two runs are only comparable when both stopped at
        // the same program point.  Using the checkpoint framework that means:
        //
        //   (a) Neither run is CHECKPOINT_MISMATCH — both reached their
        //       natural stopping condition independently. ✓ comparable.
        //
        //   (b) BOTH runs are CHECKPOINT_MISMATCH at the SAME depth — the
        //       caller already performed the re-run dance to synchronise them
        //       at a common mid-execution checkpoint. ✓ comparable.
        //
        // Any other case involving CHECKPOINT_MISMATCH means the runs stopped
        // at different program points and must not be compared directly.
        //
        // Critical subtlety: push_* runs unconditionally before
        // assert_checkpoint, so the failing event IS present in the aborting
        // run's own checkpoint record.  This makes event_count() equal on both
        // sides even when one run is a clean exit and the other is
        // CHECKPOINT_MISMATCH at the last event.  The old guard
        // `either_mismatch && d1 != d2` missed this case entirely.
        {
            size_t d1 = checkpoint_depth(r1);
            size_t d2 = checkpoint_depth(r2);
            bool either_mismatch = r1.exit_reason == exit_type::CHECKPOINT_MISMATCH ||
                                   r2.exit_reason == exit_type::CHECKPOINT_MISMATCH;
            bool both_mismatch_same_depth =
                r1.exit_reason == exit_type::CHECKPOINT_MISMATCH &&
                r2.exit_reason == exit_type::CHECKPOINT_MISMATCH &&
                d1 == d2;
            if (either_mismatch && !both_mismatch_same_depth)
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

    // ── diff_runs helpers ─────────────────────────────────────────────────────

    // Build a reg_diff_t by comparing all 16 GPRs + rflag between two States.
    // Used when no ABI is configured.
    static reg_diff_t diff_regs_no_abi(const State &s1, const State &s2)
    {
        reg_diff_t out;

#define CHECK_GPR(field, name)                    \
    if (s1.gpr.field.qword != s2.gpr.field.qword) \
        out.divergent.push_back({name, s1.gpr.field.qword, s2.gpr.field.qword});

        CHECK_GPR(rax, "rax")
        CHECK_GPR(rbx, "rbx")
        CHECK_GPR(rcx, "rcx")
            CHECK_GPR(rdx, "rdx") CHECK_GPR(rsi, "rsi") CHECK_GPR(rdi, "rdi")
                CHECK_GPR(rbp, "rbp") CHECK_GPR(rsp, "rsp") CHECK_GPR(r8, "r8")
                    CHECK_GPR(r9, "r9") CHECK_GPR(r10, "r10") CHECK_GPR(r11, "r11")
                        CHECK_GPR(r12, "r12") CHECK_GPR(r13, "r13") CHECK_GPR(r14, "r14")
                            CHECK_GPR(r15, "r15")
#undef CHECK_GPR

                                auto f1 = static_cast<uint64_t>(s1.rflag.flat);
        auto f2 = static_cast<uint64_t>(s2.rflag.flat);
        if (f1 != f2)
            out.divergent.push_back({"rflag", f1, f2});

        return out;
    }

    // Build a reg_diff_t using the ABI's get_divergent_registers().
    static reg_diff_t diff_regs_abi(const abi::CallingConvention &abi,
                                    const State &s1, const State &s2)
    {
        reg_diff_t out;
        auto tuples = abi.get_divergent_registers(s1, s2);
        out.divergent.reserve(tuples.size());
        for (auto &[name, v1, v2] : tuples)
            out.divergent.push_back({name, v1, v2});
        return out;
    }

    // Positional diff of two uint64_t sequences.
    template <typename EntryT>
    static std::vector<EntryT> diff_sequence(
        const std::vector<uint64_t> &a,
        const std::vector<uint64_t> &b,
        auto make_entry) // (size_t index, optional<uint64_t> va, optional<uint64_t> vb) -> EntryT
    {
        std::vector<EntryT> out;
        size_t n = std::max(a.size(), b.size());
        for (size_t i = 0; i < n; ++i)
        {
            std::optional<uint64_t> va = i < a.size() ? std::optional{a[i]} : std::nullopt;
            std::optional<uint64_t> vb = i < b.size() ? std::optional{b[i]} : std::nullopt;
            if (va != vb)
                out.push_back(make_entry(i, va, vb));
        }
        return out;
    }

    // Narrow which checkpoint_field first diverges at index i.
    static checkpoint_field narrow_checkpoint_field(const checkpoint_t &c1,
                                                    const checkpoint_t &c2)
    {
        if (c1.state_hash != c2.state_hash)
            return checkpoint_field::STATE;
        if (c1.mem_write_hash != c2.mem_write_hash)
            return checkpoint_field::MEM_WRITE;
        if (c1.read_hash != c2.read_hash)
            return checkpoint_field::READ;
        if (c1.ext_call_hash != c2.ext_call_hash)
            return checkpoint_field::EXT_CALL;
        // combined_hash differed but no sub-field does — caller asserts against this
        return checkpoint_field::STATE;
    }

    static checkpoint_diff_t diff_checkpoints(const run_result_t &r1,
                                              const run_result_t &r2)
    {
        checkpoint_diff_t out;
        const auto &cp1 = r1.checkpoint_record.checkpoints;
        const auto &cp2 = r2.checkpoint_record.checkpoints;
        out.len_r1 = r1.checkpoint_record.event_count();
        out.len_r2 = r2.checkpoint_record.event_count();

        static constexpr checkpoint_t kZero{};

        size_t common = std::min(cp1.size(), cp2.size());
        // Walk shared prefix (skip sentinel at [0]).
        for (size_t i = 1; i < common; ++i)
        {
            if (cp1[i].combined_hash == cp2[i].combined_hash)
                continue;

            assert((cp1[i].state_hash != cp2[i].state_hash ||
                    cp1[i].mem_write_hash != cp2[i].mem_write_hash ||
                    cp1[i].read_hash != cp2[i].read_hash ||
                    cp1[i].ext_call_hash != cp2[i].ext_call_hash) &&
                   "combined_hash diverged but no sub-field differs — hash computation bug");

            out.entries.push_back({
                i,
                narrow_checkpoint_field(cp1[i], cp2[i]),
                cp1[i],
                cp2[i],
            });
        }

        // Length divergence: emit one entry for the first beyond-end index.
        if (cp1.size() != cp2.size())
        {
            const checkpoint_t &longer_cp =
                cp1.size() > cp2.size() ? cp1[common] : kZero;
            const checkpoint_t &shorter_cp =
                cp2.size() > cp1.size() ? cp2[common] : kZero;
            out.entries.push_back({
                common,
                checkpoint_field::STATE, // placeholder for length-only divergence
                cp1.size() > cp2.size() ? longer_cp : kZero,
                cp2.size() > cp1.size() ? shorter_cp : kZero,
            });
        }

        return out;
    }

    // ── diff_result_t::print ──────────────────────────────────────────────────

    static const char *exit_type_str(exit_type e) noexcept
    {
        switch (e)
        {
        case exit_type::NATURAL_EXIT:
            return "NATURAL_EXIT";
        case exit_type::EXCEPTION:
            return "EXCEPTION";
        case exit_type::MISSING_BLOCK:
            return "MISSING_BLOCK";
        case exit_type::CHECKPOINT_MISMATCH:
            return "CHECKPOINT_MISMATCH";
        case exit_type::LAST_CHECKPOINT_REACHED:
            return "LAST_CHECKPOINT_REACHED";
        case exit_type::LOOP_LIMIT:
            return "LOOP_LIMIT";
        case exit_type::BB_LIMIT:
            return "BB_LIMIT";
        }
        return "UNKNOWN";
    }

    static const char *page_diff_kind_str(page_diff_kind k) noexcept
    {
        switch (k)
        {
        case page_diff_kind::VALUE_MISMATCH:
            return "VALUE_MISMATCH";
        case page_diff_kind::WRITE_SET_MISMATCH:
            return "WRITE_SET_MISMATCH";
        case page_diff_kind::BOTH:
            return "BOTH";
        }
        return "UNKNOWN";
    }

    void diff_result_t::print(std::ostream &os) const
    {
        os << "[DIFF]\n";

        // ── exit type ────────────────────────────────────────────────────────
        if (exit_type_diff)
        {
            os << "  exit_type: r1=" << exit_type_str(exit_type_diff->first)
               << "  r2=" << exit_type_str(exit_type_diff->second) << "\n";
        }

        // ── registers ────────────────────────────────────────────────────────
        if (reg_diff)
        {
            os << "  registers (" << reg_diff->divergent.size() << " divergent):\n";
            for (const auto &e : reg_diff->divergent)
                os << "    " << e.name
                   << ": r1=0x" << std::hex << e.val_r1
                   << "  r2=0x" << e.val_r2 << std::dec << "\n";
        }

        // ── BB trace ─────────────────────────────────────────────────────────
        if (bb_trace_diff)
        {
            const auto &d = *bb_trace_diff;
            os << "  bb_trace: r1_len=" << d.len_r1
               << "  r2_len=" << d.len_r2
               << "  (" << d.entries.size() << " divergences):\n";
            for (const auto &e : d.entries)
            {
                os << "    [" << e.index << "] r1=";
                if (e.rva_r1)
                    os << "0x" << std::hex << *e.rva_r1 << std::dec;
                else
                    os << "<absent>";
                os << "  r2=";
                if (e.rva_r2)
                    os << "0x" << std::hex << *e.rva_r2 << std::dec;
                else
                    os << "<absent>";
                os << "\n";
            }
        }

        // ── external calls ───────────────────────────────────────────────────
        if (ext_call_diff)
        {
            const auto &d = *ext_call_diff;
            os << "  ext_calls: r1_len=" << d.len_r1
               << "  r2_len=" << d.len_r2
               << "  (" << d.entries.size() << " divergences):\n";
            for (const auto &e : d.entries)
            {
                os << "    [" << e.index << "] r1=";
                if (e.addr_r1)
                    os << "0x" << std::hex << *e.addr_r1 << std::dec;
                else
                    os << "<absent>";
                os << "  r2=";
                if (e.addr_r2)
                    os << "0x" << std::hex << *e.addr_r2 << std::dec;
                else
                    os << "<absent>";
                os << "\n";
            }
        }

        // ── checkpoints ──────────────────────────────────────────────────────
        if (checkpoint_diff)
        {
            const auto &d = *checkpoint_diff;
            os << "  checkpoints: r1_events=" << d.len_r1
               << "  r2_events=" << d.len_r2
               << "  (" << d.entries.size() << " divergences):\n";
            for (const auto &e : d.entries)
            {
                os << "    [" << e.index << "] field=" << field_str(e.first_diverging_field)
                   << "\n";
                os << "      r1: state=0x" << std::hex << e.cp_r1.state_hash
                   << " mem_write=0x" << e.cp_r1.mem_write_hash
                   << " read=0x" << e.cp_r1.read_hash
                   << " ext_call=0x" << e.cp_r1.ext_call_hash << std::dec << "\n";
                os << "      r2: state=0x" << std::hex << e.cp_r2.state_hash
                   << " mem_write=0x" << e.cp_r2.mem_write_hash
                   << " read=0x" << e.cp_r2.read_hash
                   << " ext_call=0x" << e.cp_r2.ext_call_hash << std::dec << "\n";
            }
        }

        // ── memory ───────────────────────────────────────────────────────────
        if (mem_diff)
        {
            os << "  memory: " << mem_diff->page_diffs.size() << " page(s) differ:\n";
            for (const auto &pd : mem_diff->page_diffs)
            {
                os << "    page 0x" << std::hex << pd.page_addr << std::dec
                   << " [" << page_diff_kind_str(pd.kind) << "]"
                   << "  " << pd.ranges.size() << " range(s):\n";
                for (const auto &r : pd.ranges)
                {
                    os << "      0x" << std::hex << r.start << "..0x" << r.end << std::dec
                       << " (" << (r.end - r.start) << " B)"
                       << "\n";
                }
            }
        }
    }

    // ── diff_runs ─────────────────────────────────────────────────────────────

    diff_result_t diff_runs(
        const run_result_t &r1,
        const run_result_t &r2,
        const compare_config_t &cfg)
    {
        // Validate precondition: the pair must have been classified as FAIL_DIVERGED.
        // Run compare_runs internally so we can assert without forcing the caller
        // to pass in the comparison_result_t.
        [[maybe_unused]] auto cmp = compare_runs(r1, r2, cfg);
        assert(cmp.status == comparison_status::FAIL_DIVERGED &&
               "diff_runs requires a FAIL_DIVERGED pair — "
               "call compare_runs first and check the status");

        diff_result_t out;

        // ── exit type ────────────────────────────────────────────────────────
        if (r1.exit_reason != r2.exit_reason)
            out.exit_type_diff = {r1.exit_reason, r2.exit_reason};

        // ── registers ────────────────────────────────────────────────────────
        {
            reg_diff_t rd = cfg.abi
                                ? diff_regs_abi(*cfg.abi, r1.final_state, r2.final_state)
                                : diff_regs_no_abi(r1.final_state, r2.final_state);

            if (!rd.divergent.empty())
                out.reg_diff = std::move(rd);
        }

        // ── BB trace ─────────────────────────────────────────────────────────
        {
            auto entries = diff_sequence<bb_trace_diff_entry_t>(
                r1.bb_trace, r2.bb_trace,
                [](size_t i, std::optional<uint64_t> va, std::optional<uint64_t> vb)
                    -> bb_trace_diff_entry_t
                { return {i, va, vb}; });

            if (!entries.empty() || r1.bb_trace.size() != r2.bb_trace.size())
            {
                out.bb_trace_diff = bb_trace_diff_t{
                    r1.bb_trace.size(),
                    r2.bb_trace.size(),
                    std::move(entries),
                };
            }
        }

        // ── external calls ───────────────────────────────────────────────────
        {
            auto entries = diff_sequence<ext_call_diff_entry_t>(
                r1.ext_calls, r2.ext_calls,
                [](size_t i, std::optional<uint64_t> va, std::optional<uint64_t> vb)
                    -> ext_call_diff_entry_t
                { return {i, va, vb}; });

            if (!entries.empty() || r1.ext_calls.size() != r2.ext_calls.size())
            {
                out.ext_call_diff = ext_call_diff_t{
                    r1.ext_calls.size(),
                    r2.ext_calls.size(),
                    std::move(entries),
                };
            }
        }

        // ── checkpoints ──────────────────────────────────────────────────────
        {
            auto cd = diff_checkpoints(r1, r2);
            if (!cd.entries.empty())
                out.checkpoint_diff = std::move(cd);
        }

        // ── memory ───────────────────────────────────────────────────────────
        {
            auto md = r1.mem_snapshot.compare_detailed(r2.mem_snapshot);
            if (!md.equivalent)
                out.mem_diff = std::move(md);
        }

        return out;
    }

} // namespace lifted::verification
