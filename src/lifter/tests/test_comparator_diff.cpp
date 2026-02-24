#include "test_framework.hpp"
#include "verification/comparator.hpp"

#include <remill/Arch/X86/Runtime/State.h>

using namespace lifted::verification;

// ── Helpers ───────────────────────────────────────────────────────────────────

static State make_state(uint64_t rax = 0, uint64_t rbx = 0,
                        uint64_t rcx = 0, uint32_t rflags = 0x202)
{
    State s{};
    s.gpr.rax.qword = rax;
    s.gpr.rbx.qword = rbx;
    s.gpr.rcx.qword = rcx;
    s.rflag.flat = rflags;
    return s;
}

static run_result_t make_result(exit_type et = exit_type::NATURAL_EXIT)
{
    run_result_t r{};
    r.exit_reason = et;
    return r;
}

// Produce two FAIL_DIVERGED results that are structurally comparable.
// Both are NATURAL_EXIT; caller then customises them.
static std::pair<run_result_t, run_result_t> make_diverged_pair()
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::NATURAL_EXIT);
    // Give them differing register states so compare_runs reports FAIL_DIVERGED.
    r1.final_state = make_state(0xAAAA);
    r2.final_state = make_state(0xBBBB);
    return {r1, r2};
}

// ── Precondition guard ───────────────────────────────────────────────────────

// diff_runs must only be called on FAIL_DIVERGED pairs.
// Verify it does NOT assert when called on a legitimate FAIL_DIVERGED pair.
TEST(diff_runs_does_not_assert_on_fail_diverged)
{
    auto [r1, r2] = make_diverged_pair();
    // Just verify it doesn't crash.
    auto d = diff_runs(r1, r2);
    CHECK(d.reg_diff.has_value());
}

// ── Exit-type diff ────────────────────────────────────────────────────────────

TEST(diff_exit_type_same_no_diff)
{
    auto [r1, r2] = make_diverged_pair();
    // Both NATURAL_EXIT, so no exit_type_diff.
    auto d = diff_runs(r1, r2);
    CHECK(!d.exit_type_diff.has_value());
}

TEST(diff_exit_type_different_populated)
{
    auto r1 = make_result(exit_type::NATURAL_EXIT);
    auto r2 = make_result(exit_type::LOOP_LIMIT);
    // Make reg states differ so validate_runs sees FAIL_DIVERGED overall.
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);

    auto d = diff_runs(r1, r2);
    CHECK(d.exit_type_diff.has_value());
    CHECK_EQ(static_cast<int>(d.exit_type_diff->first),
             static_cast<int>(exit_type::NATURAL_EXIT));
    CHECK_EQ(static_cast<int>(d.exit_type_diff->second),
             static_cast<int>(exit_type::LOOP_LIMIT));
}

// ── Register diff ─────────────────────────────────────────────────────────────

TEST(diff_regs_no_abi_all_match_no_diff)
{
    auto r1 = make_result();
    auto r2 = make_result();
    // All regs identical → no reg_diff; but we need some other difference so
    // compare_runs yields FAIL_DIVERGED.  Use diverging bb_trace for that.
    r1.bb_trace = {0x1000};
    r2.bb_trace = {0x2000};

    auto d = diff_runs(r1, r2);
    CHECK(!d.reg_diff.has_value());
}

TEST(diff_regs_no_abi_rax_differs)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0xDEAD);
    r2.final_state = make_state(0xBEEF);

    auto d = diff_runs(r1, r2);
    CHECK(d.reg_diff.has_value());
    CHECK(!d.reg_diff->divergent.empty());
    CHECK_EQ(d.reg_diff->divergent[0].name, std::string("rax"));
    CHECK_EQ(d.reg_diff->divergent[0].val_r1, static_cast<uint64_t>(0xDEAD));
    CHECK_EQ(d.reg_diff->divergent[0].val_r2, static_cast<uint64_t>(0xBEEF));
}

TEST(diff_regs_no_abi_rflag_differs)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0, 0, 0, 0x202);
    r2.final_state = make_state(0, 0, 0, 0x246); // ZF set
    // Need other divergence too for FAIL_DIVERGED.
    r1.bb_trace = {0x1000}; // trace mismatch needed only if regs match — here they don't

    auto d = diff_runs(r1, r2);
    CHECK(d.reg_diff.has_value());
    bool found_rflag = false;
    for (const auto &e : d.reg_diff->divergent)
        if (e.name == "rflag")
        {
            found_rflag = true;
            break;
        }
    CHECK(found_rflag);
}

TEST(diff_regs_multiple_divergent_registers)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x111, 0x222, 0x333);
    r2.final_state = make_state(0x444, 0x555, 0x666);

    auto d = diff_runs(r1, r2);
    CHECK(d.reg_diff.has_value());
    // rax, rbx, rcx all differ → at least 3 entries.
    CHECK_GT(d.reg_diff->divergent.size(), static_cast<size_t>(2));
}

// ── BB trace diff ─────────────────────────────────────────────────────────────

TEST(diff_bb_trace_identical_no_diff)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.bb_trace = {0x1000, 0x1010, 0x1020};
    r2.bb_trace = {0x1000, 0x1010, 0x1020};

    auto d = diff_runs(r1, r2);
    CHECK(!d.bb_trace_diff.has_value());
}

TEST(diff_bb_trace_one_mismatch_at_index_1)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.bb_trace = {0x1000, 0x1010, 0x1020};
    r2.bb_trace = {0x1000, 0x9999, 0x1020};

    auto d = diff_runs(r1, r2);
    CHECK(d.bb_trace_diff.has_value());
    CHECK_EQ(d.bb_trace_diff->len_r1, static_cast<size_t>(3));
    CHECK_EQ(d.bb_trace_diff->len_r2, static_cast<size_t>(3));
    CHECK_EQ(d.bb_trace_diff->entries.size(), static_cast<size_t>(1));
    CHECK_EQ(d.bb_trace_diff->entries[0].index, static_cast<size_t>(1));
    CHECK(d.bb_trace_diff->entries[0].rva_r1.has_value());
    CHECK(d.bb_trace_diff->entries[0].rva_r2.has_value());
    CHECK_EQ(*d.bb_trace_diff->entries[0].rva_r1, static_cast<uint64_t>(0x1010));
    CHECK_EQ(*d.bb_trace_diff->entries[0].rva_r2, static_cast<uint64_t>(0x9999));
}

TEST(diff_bb_trace_length_mismatch_absent_rva)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.bb_trace = {0x1000, 0x1010};
    r2.bb_trace = {0x1000, 0x1010, 0x1020}; // r2 has an extra block

    auto d = diff_runs(r1, r2);
    CHECK(d.bb_trace_diff.has_value());
    CHECK_EQ(d.bb_trace_diff->len_r1, static_cast<size_t>(2));
    CHECK_EQ(d.bb_trace_diff->len_r2, static_cast<size_t>(3));
    // One length-divergence entry at index 2.
    CHECK_EQ(d.bb_trace_diff->entries.size(), static_cast<size_t>(1));
    CHECK_EQ(d.bb_trace_diff->entries[0].index, static_cast<size_t>(2));
    CHECK(!d.bb_trace_diff->entries[0].rva_r1.has_value()); // r1 ended
    CHECK(d.bb_trace_diff->entries[0].rva_r2.has_value());
    CHECK_EQ(*d.bb_trace_diff->entries[0].rva_r2, static_cast<uint64_t>(0x1020));
}

TEST(diff_bb_trace_multiple_mismatches_all_captured)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.bb_trace = {0x1000, 0xAAAA, 0x2000, 0xBBBB};
    r2.bb_trace = {0x1000, 0x1111, 0x2000, 0x2222};

    auto d = diff_runs(r1, r2);
    CHECK(d.bb_trace_diff.has_value());
    // Indices 1 and 3 differ.
    CHECK_EQ(d.bb_trace_diff->entries.size(), static_cast<size_t>(2));
    CHECK_EQ(d.bb_trace_diff->entries[0].index, static_cast<size_t>(1));
    CHECK_EQ(d.bb_trace_diff->entries[1].index, static_cast<size_t>(3));
}

// ── External call diff ────────────────────────────────────────────────────────

TEST(diff_ext_calls_identical_no_diff)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.ext_calls = {0x4000, 0x5000};
    r2.ext_calls = {0x4000, 0x5000};

    auto d = diff_runs(r1, r2);
    CHECK(!d.ext_call_diff.has_value());
}

TEST(diff_ext_calls_mismatch_at_index_0)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.ext_calls = {0x4000};
    r2.ext_calls = {0x9999};

    auto d = diff_runs(r1, r2);
    CHECK(d.ext_call_diff.has_value());
    CHECK_EQ(d.ext_call_diff->entries.size(), static_cast<size_t>(1));
    CHECK_EQ(d.ext_call_diff->entries[0].index, static_cast<size_t>(0));
    CHECK_EQ(*d.ext_call_diff->entries[0].addr_r1, static_cast<uint64_t>(0x4000));
    CHECK_EQ(*d.ext_call_diff->entries[0].addr_r2, static_cast<uint64_t>(0x9999));
}

TEST(diff_ext_calls_length_mismatch)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);
    r1.ext_calls = {0x4000, 0x5000, 0x6000};
    r2.ext_calls = {0x4000, 0x5000};

    auto d = diff_runs(r1, r2);
    CHECK(d.ext_call_diff.has_value());
    CHECK_EQ(d.ext_call_diff->len_r1, static_cast<size_t>(3));
    CHECK_EQ(d.ext_call_diff->len_r2, static_cast<size_t>(2));
    CHECK_EQ(d.ext_call_diff->entries.size(), static_cast<size_t>(1));
    CHECK_EQ(d.ext_call_diff->entries[0].index, static_cast<size_t>(2));
    CHECK(d.ext_call_diff->entries[0].addr_r1.has_value());
    CHECK(!d.ext_call_diff->entries[0].addr_r2.has_value());
}

// ── Checkpoint diff ───────────────────────────────────────────────────────────

TEST(diff_checkpoints_identical_no_diff)
{
    State s = make_state(42);
    auto r1 = make_result();
    auto r2 = make_result();

    r1.checkpoint_record.push_bb(0x1000, &s);
    r2.checkpoint_record.push_bb(0x1000, &s);

    // Need some other divergence for FAIL_DIVERGED.
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);

    auto d = diff_runs(r1, r2);
    CHECK(!d.checkpoint_diff.has_value());
}

TEST(diff_checkpoints_state_hash_diverges_at_index_1)
{
    State s1 = make_state(1);
    State s2 = make_state(999);

    auto r1 = make_result();
    auto r2 = make_result();
    r1.checkpoint_record.push_bb(0x1000, &s1);
    r2.checkpoint_record.push_bb(0x1000, &s2);
    r1.final_state = s1;
    r2.final_state = s2;

    auto d = diff_runs(r1, r2);
    CHECK(d.checkpoint_diff.has_value());
    CHECK_EQ(d.checkpoint_diff->len_r1, static_cast<size_t>(1));
    CHECK_EQ(d.checkpoint_diff->len_r2, static_cast<size_t>(1));
    CHECK_EQ(d.checkpoint_diff->entries.size(), static_cast<size_t>(1));
    CHECK_EQ(d.checkpoint_diff->entries[0].index, static_cast<size_t>(1));
    CHECK_EQ(static_cast<int>(d.checkpoint_diff->entries[0].first_diverging_field),
             static_cast<int>(checkpoint_field::STATE));
    // Raw checkpoint_t values accessible for tooling.
    CHECK_NE(d.checkpoint_diff->entries[0].cp_r1.state_hash,
             d.checkpoint_diff->entries[0].cp_r2.state_hash);
}

TEST(diff_checkpoints_mem_write_hash_diverges)
{
    auto r1 = make_result();
    auto r2 = make_result();
    r1.checkpoint_record.push_write(0x4000, 0xAA, 8);
    r2.checkpoint_record.push_write(0x4000, 0xBB, 8);

    // Need reg divergence for FAIL_DIVERGED.
    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);

    auto d = diff_runs(r1, r2);
    CHECK(d.checkpoint_diff.has_value());
    CHECK_EQ(d.checkpoint_diff->entries.size(), static_cast<size_t>(1));
    CHECK_EQ(static_cast<int>(d.checkpoint_diff->entries[0].first_diverging_field),
             static_cast<int>(checkpoint_field::MEM_WRITE));
    CHECK_NE(d.checkpoint_diff->entries[0].cp_r1.mem_write_hash,
             d.checkpoint_diff->entries[0].cp_r2.mem_write_hash);
}

TEST(diff_checkpoints_length_mismatch_captured)
{
    State s = make_state(1);
    auto r1 = make_result();
    auto r2 = make_result();

    // r1 has 2 events, r2 has 1.
    r1.checkpoint_record.push_bb(0x1000, &s);
    r1.checkpoint_record.push_bb(0x1010, &s);
    r2.checkpoint_record.push_bb(0x1000, &s);

    r1.final_state = make_state(0x1);
    r2.final_state = make_state(0x2);

    auto d = diff_runs(r1, r2);
    CHECK(d.checkpoint_diff.has_value());
    CHECK_EQ(d.checkpoint_diff->len_r1, static_cast<size_t>(2));
    CHECK_EQ(d.checkpoint_diff->len_r2, static_cast<size_t>(1));
    // First shared entry (index 1) matches; length divergence entry at index 2.
    bool found_len_entry = false;
    for (const auto &e : d.checkpoint_diff->entries)
        if (e.index == 2)
        {
            found_len_entry = true;
            break;
        }
    CHECK(found_len_entry);
}

TEST(diff_checkpoints_all_divergences_captured)
{
    State s1 = make_state(1);
    State s2 = make_state(999);
    auto r1 = make_result();
    auto r2 = make_result();

    // Push 3 events, all diverging.
    for (int i = 0; i < 3; ++i)
    {
        r1.checkpoint_record.push_bb(0x1000 + i * 0x10, &s1);
        r2.checkpoint_record.push_bb(0x1000 + i * 0x10, &s2);
    }
    r1.final_state = s1;
    r2.final_state = s2;

    auto d = diff_runs(r1, r2);
    CHECK(d.checkpoint_diff.has_value());
    // All 3 entries diverge.
    CHECK_EQ(d.checkpoint_diff->entries.size(), static_cast<size_t>(3));
}

// ── Fully identical runs (all optionals nullopt) ──────────────────────────────
// diff_runs is only callable on FAIL_DIVERGED, so we cannot test a fully
// identical pair here without triggering the precondition assert.
// Instead: verify that a pair differing *only* in one dimension produces nullopt
// for all other dimensions.

TEST(diff_only_regs_differ_other_fields_nullopt)
{
    auto r1 = make_result();
    auto r2 = make_result();
    // Only rax differs.
    r1.final_state = make_state(0xAAAA);
    r2.final_state = make_state(0xBBBB);
    // All other fields identical (empty traces, empty checkpoints, same exit).

    auto d = diff_runs(r1, r2);

    // reg_diff present.
    CHECK(d.reg_diff.has_value());
    // Everything else nullopt.
    CHECK(!d.exit_type_diff.has_value());
    CHECK(!d.bb_trace_diff.has_value());
    CHECK(!d.ext_call_diff.has_value());
    CHECK(!d.checkpoint_diff.has_value());
    CHECK(!d.mem_diff.has_value());
}
