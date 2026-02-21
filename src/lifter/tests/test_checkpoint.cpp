#include "test_framework.hpp"
#include "verification/checkpoint.hpp"

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

// ── Tests ─────────────────────────────────────────────────────────────────────

// Two identical BB + write sequences produce equal records.
TEST(checkpoint_identical_sequences)
{
    State s = make_state(0xdeadbeef, 0, 0, 0x202);

    checkpoint_record_t a, b;

    a.push_bb(0x1000, &s);
    a.push_write(0x4000, 0xAA, 8);
    a.push_bb(0x1010, &s);

    b.push_bb(0x1000, &s);
    b.push_write(0x4000, 0xAA, 8);
    b.push_bb(0x1010, &s);

    CHECK(a == b);
}

// A single differing BB rva causes diverging hashes at that event index.
TEST(checkpoint_diverge_on_bb)
{
    State s = make_state(1);

    checkpoint_record_t a, b;

    a.push_bb(0x1000, &s);
    b.push_bb(0x1000, &s);

    // Identical so far
    CHECK_EQ(a.final_hash(), b.final_hash());

    // Second BB: same state, different rva
    a.push_bb(0x1010, &s);
    b.push_bb(0x2000, &s);

    CHECK(a != b);
    CHECK_NE(a.checkpoints[2].state_hash, b.checkpoints[2].state_hash);
    CHECK_NE(a.checkpoints[2].combined_hash, b.checkpoints[2].combined_hash);
    // Mem-write hash should still be equal (no writes happened)
    CHECK_EQ(a.checkpoints[2].mem_write_hash, b.checkpoints[2].mem_write_hash);
}

// A single differing write value causes divergence in mem_write_hash.
TEST(checkpoint_diverge_on_write)
{
    State s = make_state();

    checkpoint_record_t a, b;

    a.push_bb(0x1000, &s);
    b.push_bb(0x1000, &s);

    a.push_write(0x4000, 0xAA, 8);
    b.push_write(0x4000, 0xBB, 8); // value differs

    CHECK(a != b);
    CHECK_NE(a.checkpoints[2].mem_write_hash, b.checkpoints[2].mem_write_hash);
    // State hash should still match (same BB before)
    CHECK_EQ(a.checkpoints[2].state_hash, b.checkpoints[2].state_hash);
}

// push_read is sensitive to differing values.
TEST(checkpoint_read_sensitive)
{
    checkpoint_record_t a, b;

    a.push_read(0x5000, 0x11, 4);
    b.push_read(0x5000, 0xFF, 4);

    CHECK(a != b);
    CHECK_NE(a.checkpoints[1].read_hash, b.checkpoints[1].read_hash);
}

// Records of different sizes are not equal.
TEST(checkpoint_size_mismatch)
{
    State s = make_state();

    checkpoint_record_t a, b;

    a.push_bb(0x1000, &s);
    a.push_bb(0x1010, &s);
    a.push_bb(0x1020, &s);

    b.push_bb(0x1000, &s);
    b.push_bb(0x1010, &s);

    CHECK(a != b);
    CHECK_EQ(a.event_count(), static_cast<size_t>(3));
    CHECK_EQ(b.event_count(), static_cast<size_t>(2));
}

// Empty records are equal.
TEST(checkpoint_empty_records_equal)
{
    checkpoint_record_t a, b;
    CHECK(a == b);
    CHECK_EQ(a.final_hash(), b.final_hash());
    CHECK_EQ(a.event_count(), static_cast<size_t>(0));
}

// push_* returns the new combined_hash (same as final_hash() after the call).
TEST(checkpoint_push_returns_combined_hash)
{
    State s = make_state(42);
    checkpoint_record_t rec;

    uint64_t h = rec.push_bb(0x1000, &s);
    CHECK_EQ(h, rec.final_hash());
    CHECK_EQ(h, rec.checkpoints[1].combined_hash);
}

// Different-width writes to same address+value produce distinct records.
TEST(checkpoint_write_size_sensitive)
{
    checkpoint_record_t a, b;
    a.push_write(0x1000, 0xAB, 4);
    b.push_write(0x1000, 0xAB, 8);

    CHECK(a != b);
}

// config_t: DEFAULT flags cover BB, MEM_WRITE, EXT_CALL but not MEM_READ.
TEST(checkpoint_config_default_flags)
{
    checkpoint_config_t cfg;
    CHECK(has_flag(cfg.flags, record_on_flags::BB));
    CHECK(has_flag(cfg.flags, record_on_flags::MEM_WRITE));
    CHECK(has_flag(cfg.flags, record_on_flags::EXT_CALL));
    CHECK(!has_flag(cfg.flags, record_on_flags::MEM_READ));
    CHECK(cfg.prev_record == nullptr);
}

// Caller-driven comparison via push_* return values.
// Simulates what a verifier_state subclass would do.
TEST(checkpoint_caller_driven_comparison)
{
    State s1 = make_state(1);
    State s2 = make_state(999); // different rax

    checkpoint_record_t ref;
    ref.push_bb(0x1000, &s1);
    ref.push_bb(0x1010, &s1);

    checkpoint_config_t cfg;
    cfg.prev_record = &ref;

    checkpoint_record_t rec;

    // Event 1: same — hashes should match
    uint64_t h1 = rec.push_bb(0x1000, &s1);
    uint64_t prev_h1 = cfg.prev_record->checkpoints[1].combined_hash;
    CHECK_EQ(h1, prev_h1);

    // Event 2: different state — hashes should diverge
    uint64_t h2 = rec.push_bb(0x1010, &s2);
    uint64_t prev_h2 = cfg.prev_record->checkpoints[2].combined_hash;
    CHECK_NE(h2, prev_h2);
}

// hash_state must ignore uninitialised/padding bytes outside GPRs+flags.
TEST(checkpoint_hash_state_ignores_padding)
{
    State a{}, b{};

    a.gpr.rax.qword = b.gpr.rax.qword = 0x111;
    a.gpr.rbx.qword = b.gpr.rbx.qword = 0x222;
    a.gpr.rcx.qword = b.gpr.rcx.qword = 0x333;
    a.gpr.rdx.qword = b.gpr.rdx.qword = 0x444;
    a.gpr.rsi.qword = b.gpr.rsi.qword = 0x555;
    a.gpr.rdi.qword = b.gpr.rdi.qword = 0x666;
    a.gpr.rbp.qword = b.gpr.rbp.qword = 0x777;
    a.gpr.rsp.qword = b.gpr.rsp.qword = 0x888;
    a.gpr.r8.qword = b.gpr.r8.qword = 0xAA;
    a.gpr.r9.qword = b.gpr.r9.qword = 0xBB;
    a.gpr.r10.qword = b.gpr.r10.qword = 0xCC;
    a.gpr.r11.qword = b.gpr.r11.qword = 0xDD;
    a.gpr.r12.qword = b.gpr.r12.qword = 0xEE;
    a.gpr.r13.qword = b.gpr.r13.qword = 0xFF;
    a.gpr.r14.qword = b.gpr.r14.qword = 0x1234;
    a.gpr.r15.qword = b.gpr.r15.qword = 0x5678;
    a.rflag.flat = b.rflag.flat = 0x202;

    // Dirty vector registers in b — must not affect hash_state.
    static_assert(sizeof(b.vec) > 0, "expected vec registers in X86State");
    auto *raw = reinterpret_cast<unsigned char *>(&b.vec);
    for (size_t i = 0; i < sizeof(b.vec); ++i)
        raw[i] = static_cast<unsigned char>(i ^ 0xA5);

    CHECK_EQ(checkpoint_record_t::hash_state(&a),
             checkpoint_record_t::hash_state(&b));
}

// hash_mix: mix is not commutative.
TEST(hash_mix_order_sensitive)
{
    uint64_t ab = lifted::hash::mix(0xDEAD, 0xBEEF);
    uint64_t ba = lifted::hash::mix(0xBEEF, 0xDEAD);
    CHECK_NE(ab, ba);
}

// mix_bytes: deterministic and content-sensitive.
TEST(hash_mix_bytes_consistent)
{
    const char data[] = "hello world checkpoint";
    const char data2[] = "hello world checkpoinX";

    uint64_t h1 = lifted::hash::mix_bytes(0, data, sizeof(data) - 1);
    uint64_t h2 = lifted::hash::mix_bytes(0, data, sizeof(data) - 1);
    uint64_t h3 = lifted::hash::mix_bytes(0, data2, sizeof(data2) - 1);

    CHECK_EQ(h1, h2);
    CHECK_NE(h1, h3);
}
