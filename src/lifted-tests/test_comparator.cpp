#include "test_framework.hpp"
#include "verification/comparator.hpp"

#include <remill/Arch/X86/Runtime/State.h>

using namespace lifted::verification;

// ── Helpers ───────────────────────────────────────────────────────────────────

static State make_state(uint64_t rax = 0, uint64_t rbx = 0, uint32_t rflags = 0x202)
{
    State s{};
    s.gpr.rax.qword = rax;
    s.gpr.rbx.qword = rbx;
    s.rflag.flat = rflags;
    return s;
}

static run_result_t make_result(exit_type et)
{
    run_result_t r{};
    r.exit_reason = et;
    r.checkpoint_record.sync_on = event_flags::DEFAULT;
    r.checkpoint_record.compare_dims = compare_dimension_flags::DEFAULT;
    return r;
}

// ── Phase 1: FAIL_INCOMPARABLE ────────────────────────────────────────────────

// Guest exceptions are incomparable because executor synchronisation is not guaranteed.
TEST(comparator_natural_exit_vs_exception_incomparable)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::EXCEPTION);
    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_INCOMPARABLE));
    // No dimension verdicts issued.
    CHECK(!res.dimensions.exit_type_match);
    CHECK(!res.dimensions.checkpoint_match);
}

// Missing lifted coverage is a real divergence, not an incomparable fault.
TEST(comparator_natural_exit_vs_missing_block_diverged)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::MISSING_BLOCK);
    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.exit_type_match);
    CHECK(res.dimensions.checkpoint_match);
}

// Both guest exceptions are still incomparable (current policy — easy to change via is_fault()).
TEST(comparator_both_exception_incomparable)
{
    auto r1 = make_result(exit_type::EXCEPTION);
    auto r2 = make_result(exit_type::EXCEPTION);
    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_INCOMPARABLE));
}

// ── Phase 2: NEEDS_RERUN ──────────────────────────────────────────────────────

// r2 stopped at CHECKPOINT_MISMATCH at index 3; r1 ran to 5 events.
TEST(comparator_needs_rerun_r2_shallower)
{
    State s = make_state(42);

    auto r1 = make_result(exit_type::NATURAL_EXIT);
    for (int i = 0; i < 5; ++i)
        r1.checkpoint_record.push_bb(0x1000 + i * 0x10, &s, 0);

    auto r2 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r2.failed_checkpoint_idx = 3;
    for (int i = 0; i < 3; ++i)
        r2.checkpoint_record.push_bb(0x1000 + i * 0x10, &s, 0);

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::NEEDS_RERUN));
    CHECK(res.needs_rerun_at_index.has_value());
    CHECK_EQ(*res.needs_rerun_at_index, static_cast<size_t>(3));
}

// Symmetric: both CHECKPOINT_MISMATCH but at different indices.
TEST(comparator_needs_rerun_symmetric_different_indices)
{
    auto r1 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r1.failed_checkpoint_idx = 4;

    auto r2 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r2.failed_checkpoint_idx = 2;

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::NEEDS_RERUN));
    CHECK(res.needs_rerun_at_index.has_value());
    CHECK_EQ(*res.needs_rerun_at_index, static_cast<size_t>(2));
}

// ── Phase 3: Proceed — PASS ───────────────────────────────────────────────────

// Two default-constructed NATURAL_EXIT runs: all dimensions trivially match.
TEST(comparator_pass_identical_empty_runs)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::PASS));
    CHECK(res.dimensions.exit_type_match);
    CHECK(res.dimensions.checkpoint_match);
    CHECK(res.dimensions.reg_state_match);
    CHECK(res.dimensions.mem_snapshot_match);
    CHECK(res.dimensions.bb_trace_match);
    CHECK(res.dimensions.ext_calls_match);
    CHECK(!res.first_checkpoint_divergence.has_value());
    CHECK(!res.first_trace_divergence.has_value());
    CHECK(!res.first_ext_call_divergence.has_value());
}

// Both CHECKPOINT_MISMATCH at the same index with identical records: should proceed.
TEST(comparator_pass_same_mismatch_index)
{
    State s = make_state(7);

    auto r1 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r1.failed_checkpoint_idx = 3;
    auto r2 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r2.failed_checkpoint_idx = 3;

    for (int i = 0; i < 3; ++i)
    {
        r1.checkpoint_record.push_bb(0x1000 + i * 0x10, &s, 0);
        r2.checkpoint_record.push_bb(0x1000 + i * 0x10, &s, 0);
    }

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::PASS));
    CHECK(res.dimensions.exit_type_match);
    CHECK(res.dimensions.checkpoint_match);
}

// Clean × Clean: LOOP_LIMIT vs LAST_CHECKPOINT_REACHED — not incomparable.
// Exit types differ, so it ends up FAIL_DIVERGED on that dimension, but it
// is definitely comparable (the pair enters Phase 3).
TEST(comparator_clean_cross_clean_proceeds)
{
    auto r1 = make_result(exit_type::LOOP_LIMIT);
    auto r2 = make_result(exit_type::LAST_CHECKPOINT_REACHED);

    auto res = compare_runs(r1, r2);
    CHECK(static_cast<int>(res.status) !=
          static_cast<int>(comparison_status::FAIL_INCOMPARABLE));
    CHECK(static_cast<int>(res.status) !=
          static_cast<int>(comparison_status::NEEDS_RERUN));
    // Exit types differ → at least one dimension false → FAIL_DIVERGED.
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.exit_type_match);
}

// ── Phase 3: Proceed — FAIL_DIVERGED dimensions ───────────────────────────────

// Checkpoint state_hash diverges (same RVA, different register state).
TEST(comparator_fail_checkpoint_state_hash)
{
    State s1 = make_state(1);
    State s2 = make_state(999); // different rax

    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    r1.checkpoint_record.push_bb(0x1000, &s1, 0);
    r2.checkpoint_record.push_bb(0x1000, &s2, 0);

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.checkpoint_match);
    CHECK(res.first_checkpoint_divergence.has_value());
    CHECK_EQ(res.first_checkpoint_divergence->index, static_cast<size_t>(1));
    CHECK_EQ(static_cast<int>(res.first_checkpoint_divergence->field),
             static_cast<int>(checkpoint_field::STATE));
}

// Checkpoint mem_write_hash diverges (same address, different value).
TEST(comparator_fail_checkpoint_mem_write_hash)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    r1.checkpoint_record.push_write(0x4000, 0xAA, 8, 0);
    r2.checkpoint_record.push_write(0x4000, 0xBB, 8, 0); // different write value

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(res.first_checkpoint_divergence.has_value());
    CHECK_EQ(static_cast<int>(res.first_checkpoint_divergence->field),
             static_cast<int>(checkpoint_field::MEM_WRITE));
}

// BB trace diverges at index 1.
TEST(comparator_fail_bb_trace_mismatch)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    r1.bb_trace = {0x1000, 0x1010, 0x1020};
    r2.bb_trace = {0x1000, 0x9999, 0x1020};

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.bb_trace_match);
    CHECK(res.first_trace_divergence.has_value());
    CHECK_EQ(*res.first_trace_divergence, static_cast<size_t>(1));
}

// Ext calls diverge at index 1.
TEST(comparator_fail_ext_calls_mismatch)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    r1.ext_calls = {0x4000, 0x5000};
    r2.ext_calls = {0x4000, 0x6666};

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.ext_calls_match);
    CHECK(res.first_ext_call_divergence.has_value());
    CHECK_EQ(*res.first_ext_call_divergence, static_cast<size_t>(1));
}

// ── NEEDS_RERUN: equal-depth edge cases ──────────────────────────────────────

// Bug regression: one NATURAL_EXIT with N events, one CHECKPOINT_MISMATCH at
// depth N.  push_* runs before assert_checkpoint, so the failing event IS in
// the aborting run's own record and event_count() == N on both sides.  The old
// guard (`either_mismatch && d1 != d2`) missed this and let a Phase-3
// comparison proceed with final states at different program points.
TEST(comparator_needs_rerun_equal_depth_one_natural_one_mismatch)
{
    State s1 = make_state(1);
    State s2 = make_state(999); // diverged state

    // Run 1: free run, 2 BB events, natural exit.
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    r1.checkpoint_record.push_bb(0x1000, &s1, 0);
    r1.checkpoint_record.push_bb(0x1010, &s1, 0);

    // Run 2: assertion mode, fails at event 2.
    // The failing event is pushed before the abort → event_count() == 2.
    auto r2 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r2.failed_checkpoint_idx = 2;
    r2.checkpoint_record.push_bb(0x1000, &s1, 0);
    r2.checkpoint_record.push_bb(0x1010, &s2, 0); // diverged

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::NEEDS_RERUN));
    CHECK(res.needs_rerun_at_index.has_value());
    CHECK_EQ(*res.needs_rerun_at_index, static_cast<size_t>(2));
}

// Symmetric: CHECKPOINT_MISMATCH first, NATURAL_EXIT second.
TEST(comparator_needs_rerun_equal_depth_one_mismatch_one_natural)
{
    State s1 = make_state(1);
    State s2 = make_state(999);

    auto r1 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r1.failed_checkpoint_idx = 2;
    r1.checkpoint_record.push_bb(0x1000, &s2, 0);
    r1.checkpoint_record.push_bb(0x1010, &s2, 0);

    auto r2 = make_result(exit_type::NATURAL_EXIT);
    r2.checkpoint_record.push_bb(0x1000, &s1, 0);
    r2.checkpoint_record.push_bb(0x1010, &s1, 0);

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::NEEDS_RERUN));
    CHECK_EQ(*res.needs_rerun_at_index, static_cast<size_t>(2));
}

// One LOOP_LIMIT (clean, non-mismatch exit) + one CHECKPOINT_MISMATCH at the
// same depth: still NEEDS_RERUN.
TEST(comparator_needs_rerun_loop_limit_plus_mismatch_equal_depth)
{
    State s = make_state(42);

    auto r1 = make_result(exit_type::LOOP_LIMIT);
    r1.checkpoint_record.push_bb(0x1000, &s, 0);

    auto r2 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r2.failed_checkpoint_idx = 1;
    r2.checkpoint_record.push_bb(0x1000, &s, 0); // even matching hash: still NEEDS_RERUN

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::NEEDS_RERUN));
    CHECK_EQ(*res.needs_rerun_at_index, static_cast<size_t>(1));
}

// After the re-run dance: BOTH CHECKPOINT_MISMATCH at the same depth.
// This must NOT return NEEDS_RERUN — Phase 3 comparison is valid.
TEST(comparator_both_mismatch_same_depth_proceeds_to_phase3)
{
    State s1 = make_state(1);
    State s2 = make_state(999);

    auto r1 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r1.failed_checkpoint_idx = 2;
    r1.checkpoint_record.push_bb(0x1000, &s1, 0);
    r1.checkpoint_record.push_bb(0x1010, &s1, 0);

    auto r2 = make_result(exit_type::CHECKPOINT_MISMATCH);
    r2.failed_checkpoint_idx = 2;
    r2.checkpoint_record.push_bb(0x1000, &s1, 0);
    r2.checkpoint_record.push_bb(0x1010, &s2, 0); // diverges at index 2

    auto res = compare_runs(r1, r2);
    CHECK(static_cast<int>(res.status) !=
          static_cast<int>(comparison_status::NEEDS_RERUN));
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.checkpoint_match);
}

// ── Checkpoint flag guards ────────────────────────────────────────────────────

// If BB flag is absent in either record, state_hash shortcut must NOT fire —
// the state_hash stays zero and zero==zero cannot mean "traces match".
// Instead the comparator falls back to bb_trace comparison, which may diverge.
TEST(comparator_no_bb_flag_falls_back_to_trace_comparison)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);

    // r1 records BB events; r2 does not (NONE flags).
    r1.checkpoint_record.sync_on = event_flags::BB;
    r2.checkpoint_record.sync_on = event_flags::NONE;

    // BB traces differ — should be detected via full comparison.
    r1.bb_trace = {0x1000, 0x1010};
    r2.bb_trace = {0x1000, 0x9999};

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(!res.dimensions.bb_trace_match);
    CHECK(res.first_trace_divergence.has_value());
    CHECK_EQ(*res.first_trace_divergence, static_cast<size_t>(1));
}

// If MEM_WRITE flag absent in one record, mem shortcut must not fire even if
// mem_write_hash happens to be zero in both (no writes in that run).
TEST(comparator_no_mem_write_flag_falls_back_to_snapshot_comparison)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);

    r1.checkpoint_record.sync_on = event_flags::MEM_WRITE;
    r2.checkpoint_record.sync_on = event_flags::NONE; // no write recording

    // Both have zero mem_write_hash (no writes pushed), but we can't use the
    // shortcut.  The actual snapshots are empty (default-constructed) and
    // therefore equivalent, so mem_snapshot_match should still be true via
    // the full compare() path.
    auto res = compare_runs(r1, r2);
    CHECK(res.dimensions.mem_snapshot_match);
}

// state_hash shortcut: if BB flag in both and final state_hash agrees,
// bb_trace_match should be true even when comparing via shortcut (no walk).
TEST(comparator_bb_state_hash_shortcut_fires)
{
    State s = make_state(42);

    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);

    r1.checkpoint_record.sync_on = event_flags::BB;
    r2.checkpoint_record.sync_on = event_flags::BB;

    // Push identical BB events to both — state_hashes will match.
    r1.checkpoint_record.push_bb(0x1000, &s, 0);
    r2.checkpoint_record.push_bb(0x1000, &s, 0);

    // Provide matching bb_trace vectors so the result is PASS overall.
    r1.bb_trace = {0x1000};
    r2.bb_trace = {0x1000};

    auto res = compare_runs(r1, r2);
    CHECK(res.dimensions.bb_trace_match);
    // combined_hash also matches → checkpoint_match = true.
    CHECK(res.dimensions.checkpoint_match);
}

// ext_call_hash shortcut: EXT_CALL flag in both, matching hash → ext_calls_match.
TEST(comparator_ext_call_hash_shortcut_fires)
{
    State s = make_state(1);

    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);

    r1.checkpoint_record.sync_on = event_flags::EXT_CALL;
    r2.checkpoint_record.sync_on = event_flags::EXT_CALL;

    r1.checkpoint_record.push_ext_call(0x4000, &s, 0);
    r2.checkpoint_record.push_ext_call(0x4000, &s, 0);

    r1.ext_calls = {0x4000};
    r2.ext_calls = {0x4000};

    auto res = compare_runs(r1, r2);
    CHECK(res.dimensions.ext_calls_match);
}

// mem_write_hash shortcut: MEM_WRITE flag in both, matching hash → mem_snapshot_match.
TEST(comparator_mem_write_hash_shortcut_fires)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);

    r1.checkpoint_record.sync_on = event_flags::MEM_WRITE;
    r2.checkpoint_record.sync_on = event_flags::MEM_WRITE;

    r1.checkpoint_record.push_write(0x4000, 0xAB, 8, 0);
    r2.checkpoint_record.push_write(0x4000, 0xAB, 8, 0);

    auto res = compare_runs(r1, r2);
    CHECK(res.dimensions.mem_snapshot_match);
    // Shortcut fired → no detailed snapshot walk; result should still be correct.
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::PASS));
}

TEST(comparator_strict_write_sequence_detects_divergence_despite_equal_memory)
{
    constexpr uint64_t kAddr = 0x4000;
    constexpr uint64_t kValue = 0x1122334455667788ULL;

    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);

    r1.checkpoint_record.sync_on = event_flags::MEM_WRITE;
    r2.checkpoint_record.sync_on = event_flags::MEM_WRITE;

    paged_memory_state mem1(0x1234);
    paged_memory_state mem2(0x1234);

    mem1.write64(kAddr, kValue);
    r1.checkpoint_record.push_write(
        kAddr, kValue, 8, mem1.memory_contents_digest().combined_hash());
    r1.mem_snapshot = paged_memory_state::finalize(std::move(mem1));

    mem2.write32(kAddr + 4, 0x11223344U);
    r2.checkpoint_record.push_write(
        kAddr + 4, 0x11223344U, 4, mem2.memory_contents_digest().combined_hash());
    mem2.write32(kAddr, 0x55667788U);
    r2.checkpoint_record.push_write(
        kAddr, 0x55667788U, 4, mem2.memory_contents_digest().combined_hash());
    r2.mem_snapshot = paged_memory_state::finalize(std::move(mem2));

    auto res = compare_runs(r1, r2);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::FAIL_DIVERGED));
    CHECK(res.dimensions.mem_snapshot_match);
    CHECK(!res.dimensions.write_sequence_match);
    CHECK(!res.dimensions.checkpoint_match);
}

TEST(comparator_relaxed_profile_accepts_equal_final_memory_without_sync)
{
    constexpr uint64_t kAddr = 0x5000;
    constexpr uint64_t kValue = 0x1122334455667788ULL;

    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    r1.checkpoint_record.sync_on = event_flags::NONE;
    r2.checkpoint_record.sync_on = event_flags::NONE;

    paged_memory_state mem1(0x1234);
    paged_memory_state mem2(0x1234);
    mem1.write64(kAddr, kValue);
    mem2.write32(kAddr + 4, 0x11223344U);
    mem2.write32(kAddr, 0x55667788U);

    r1.mem_snapshot = paged_memory_state::finalize(std::move(mem1));
    r2.mem_snapshot = paged_memory_state::finalize(std::move(mem2));

    compare_config_t cfg;
    cfg.dimensions = compare_dimension_flags::REG_STATE |
                     compare_dimension_flags::MEM_CONTENTS;

    auto res = compare_runs(r1, r2, cfg);
    CHECK_EQ(static_cast<int>(res.status),
             static_cast<int>(comparison_status::PASS));
    CHECK(res.dimensions.mem_snapshot_match);
    CHECK(res.dimensions.reg_state_match);
    CHECK(res.dimensions.checkpoint_match);
}
