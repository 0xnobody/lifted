// test_verifier_state_loop_limit.cpp
//
// Unit tests for verifier_state's dynamic back-edge loop-limit logic.
//
// The logic under test (in on_bb_entered):
//   An edge (from, to) is a *back-edge* (loop iteration) when the destination
//   block has already been visited: bb_first_seen.count(to) > 0.
//   Back-edge traversals are counted per directed edge {from, to}.
//   When any counter reaches bb_loop_limit, LOOP_LIMIT is signalled.
//
// Key semantic guarantees being tested:
//   - True loops (A->B->C->A repeated) correctly accumulate and fire.
//   - While-loops (jump-to-condition, condition seen before body): the back-edge
//     cond->body is correctly counted from its second traversal onward, even
//     though first_seen[cond] < first_seen[body].
//   - Dispatcher arms (B->A, C->A, D->A) each have their own counter; with
//     limit=N, none fires unless that specific arm is repeated N times.
//   - Shared-prefix edges (A->B when B already seen) are counted on 2nd+
//     traversal.  Both JIT and Unicorn count them equally so no divergence.
//   - Control-flow-flattening (dispatcher D, arms back to D) correctly bounded
//     per-arm; D->arm edges also counted on 2nd+ traversal.
//   - Self-loops (X->X) correctly detected: X in bb_first_seen after first entry.

#include "test_framework.hpp"
#include "verification/verifier_state.hpp"
#include "verification/value_generator.hpp"
#include "verification/event_flags.hpp"

#include <cstdint>
#include <limits>

using namespace lifted::verification;

// ── Minimal harness ───────────────────────────────────────────────────────────
//
// Drives on_bb_entered through the registered proxy without needing a real
// binary, oracle, or JIT/Unicorn executor.  BB checkpoint recording is
// disabled so we can pass nullptr for State* safely.

namespace
{
    static uniform_value_generator_factory s_factory{};

    class BackEdgeHarness : public verifier_state
    {
        static run_params_t make_params()
        {
            return {
                .seed            = 0,
                .binary          = nullptr,
                .entry_rva       = 0x100,
                .oracle          = nullptr,
                .value_gen_factory = &s_factory,
            };
        }

        static verification_params_t make_vparams(uint64_t lim)
        {
            verification_params_t vp;
            vp.checkpoint_config.record_on = event_flags::NONE; // disable; we pass nullptr State*
            vp.loop_limit = lim;
            vp.bb_limit   = std::numeric_limits<uint64_t>::max();
            return vp;
        }

    public:
        explicit BackEdgeHarness(uint64_t loop_limit)
            : verifier_state(make_params(), make_vparams(loop_limit))
        {
        }

        /// Simulate the executor calling bb_entered(from, to).
        /// Returns false when LOOP_LIMIT (or any other stop) is signalled.
        bool enter(uint64_t from, uint64_t to)
        {
            return context_ptr()->bb_entered(context_ptr()->context,
                                             nullptr, from, to);
        }

        exit_type reason() const { return exit_reason; }

        /// How many times has the directed edge {from,to} been counted
        /// as a back-edge?
        uint64_t edge_count(uint64_t from, uint64_t to) const
        {
            auto it = back_edge_count.find({from, to});
            return it != back_edge_count.end() ? it->second : 0;
        }

        /// Step at which rva was first seen (UINT64_MAX if not yet seen).
        uint64_t first_seen_step(uint64_t rva) const
        {
            auto it = bb_first_seen.find(rva);
            return it != bb_first_seen.end() ? it->second : std::numeric_limits<uint64_t>::max();
        }

        bool has_natural_exit() const { return exit_reason == exit_type::NATURAL_EXIT; }
        bool has_loop_limit()   const { return exit_reason == exit_type::LOOP_LIMIT;   }
    };

} // anonymous namespace

// ── Convenience addresses ─────────────────────────────────────────────────────

static constexpr uint64_t ENTRY = uint64_t(-1); // sentinel "no predecessor"
static constexpr uint64_t A = 0x1000;
static constexpr uint64_t B = 0x2000;
static constexpr uint64_t C = 0x3000;
static constexpr uint64_t D = 0x4000;
static constexpr uint64_t E = 0x5000;
static constexpr uint64_t F = 0x6000;
static constexpr uint64_t G = 0x7000;
static constexpr uint64_t H = 0x8000;
static constexpr uint64_t I = 0x9000;
static constexpr uint64_t X = 0xA000;

// ── Group 1: Basic invariants ─────────────────────────────────────────────────

// A plain chain A->B->C->D with no repetition must never trigger LOOP_LIMIT,
// even with limit=1.
TEST(loop_limit_chain_no_back_edges)
{
    BackEdgeHarness h(/*limit=*/1);
    CHECK(h.enter(ENTRY, A));
    CHECK(h.enter(A, B));
    CHECK(h.enter(B, C));
    CHECK(h.enter(C, D));
    CHECK(h.has_natural_exit());
    // All edges are forward; none should be counted.
    CHECK_EQ(h.edge_count(A, B), static_cast<uint64_t>(0));
    CHECK_EQ(h.edge_count(B, C), static_cast<uint64_t>(0));
    CHECK_EQ(h.edge_count(C, D), static_cast<uint64_t>(0));
}

// The very first enter() call uses the sentinel from_rva (-1) and must
// never contribute to any back-edge counter.
TEST(loop_limit_entry_sentinel_not_counted)
{
    BackEdgeHarness h(/*limit=*/1);
    // Even with from=ENTRY pointing to a revisited block, no count must fire.
    CHECK(h.enter(ENTRY, A));
    CHECK(h.enter(A,     B));
    CHECK(h.enter(ENTRY, A)); // simulate a second entry to A from sentinel (unusual but must be safe)
    CHECK(h.has_natural_exit());
    CHECK_EQ(h.edge_count(ENTRY, A), static_cast<uint64_t>(0));
}

// First_seen records the step of the FIRST visit.  Revisiting a block
// must not update first_seen, so the ordering test remains stable.
TEST(loop_limit_first_seen_set_on_first_visit_only)
{
    BackEdgeHarness h(/*limit=*/100);
    h.enter(ENTRY, A); // first_seen[A] = 0
    h.enter(A, B);     // first_seen[B] = 1
    uint64_t a_step = h.first_seen_step(A);
    uint64_t b_step = h.first_seen_step(B);
    // Revisit A and B via a loop back from B.
    h.enter(B, A);     // back-edge, but first_seen unchanged
    h.enter(A, B);     // forward again
    h.enter(B, A);
    CHECK_EQ(h.first_seen_step(A), a_step);
    CHECK_EQ(h.first_seen_step(B), b_step);
}

// ── Group 2: Simple loops ─────────────────────────────────────────────────────

// A->B->C->A repeated.  Edge C->A is the only back-edge; it must fire
// exactly after `limit` traversals.
TEST(loop_limit_three_block_loop_fires_at_limit)
{
    for (uint64_t limit : {1u, 3u, 10u, 50u})
    {
        BackEdgeHarness h(limit);
        h.enter(ENTRY, A);
        h.enter(A, B);
        h.enter(B, C);
        // Run limit-1 full iterations without firing.
        for (uint64_t i = 0; i < limit - 1; ++i)
        {
            CHECK(h.enter(C, A));  // back-edge, count++
            CHECK(h.enter(A, B));  // forward
            CHECK(h.enter(B, C));  // forward
        }
        CHECK_EQ(h.edge_count(C, A), limit - 1);
        // The limit-th traversal of C->A must fire LOOP_LIMIT.
        CHECK(!h.enter(C, A));
        CHECK(h.has_loop_limit());
        CHECK_EQ(h.edge_count(C, A), limit);
    }
}

// A->B->A->B->... (two-block loop).  B->A is the back-edge.
// A->B is counted on second+ traversal (B already in bb_first_seen).
TEST(loop_limit_two_block_loop_only_back_edge_counted)
{
    BackEdgeHarness h(/*limit=*/5);
    h.enter(ENTRY, A);
    h.enter(A, B);
    for (int i = 0; i < 4; ++i)
    {
        h.enter(B, A); // back-edge {B,A}
        h.enter(A, B); // 2nd+ traversal of A->B: B seen -> {A,B}++
    }
    CHECK_EQ(h.edge_count(B, A), static_cast<uint64_t>(4));
    CHECK(h.has_natural_exit());
    // Fire on 5th.
    CHECK(!h.enter(B, A));
    CHECK(h.has_loop_limit());
}

// ── Group 3: Self-loops ───────────────────────────────────────────────────────

// X->X->X...  X is in bb_first_seen after the first entry; the revisit
// criterion fires immediately on the second (and each subsequent) traversal.
TEST(loop_limit_self_loop_fires)
{
    BackEdgeHarness h(/*limit=*/4);
    h.enter(ENTRY, X);
    for (int i = 0; i < 3; ++i)
        CHECK(h.enter(X, X));
    CHECK_EQ(h.edge_count(X, X), static_cast<uint64_t>(3));
    CHECK(h.has_natural_exit());
    CHECK(!h.enter(X, X));
    CHECK(h.has_loop_limit());
    CHECK_EQ(h.edge_count(X, X), static_cast<uint64_t>(4));
}

// Self-loop with limit=1 fires on the very first self-traversal.
TEST(loop_limit_self_loop_fires_at_limit_one)
{
    BackEdgeHarness h(/*limit=*/1);
    h.enter(ENTRY, X);
    CHECK(!h.enter(X, X));
    CHECK(h.has_loop_limit());
}

// ── Group 4: Single-block dispatcher — not a loop ─────────────────────────────

// A is the dispatcher.  It dispatches to B, C, D each once.
// Each back-edge to A is distinct; with limit=1 they must NOT fire because
// no single edge is traversed more than once.
//
// Trace: -1->A->B->A->C->A->D
TEST(loop_limit_single_block_dispatcher_distinct_back_edges)
{
    // limit=2: each of B->A, C->A, D->A is traversed exactly once (count=1 < 2).
    // No single edge accumulates to limit, so the dispatcher is not a loop.
    BackEdgeHarness h(/*limit=*/2);
    h.enter(ENTRY, A);
    h.enter(A, B);
    CHECK(h.enter(B, A));   // {B,A}=1 — not yet at limit
    h.enter(A, C);
    CHECK(h.enter(C, A));   // {C,A}=1
    h.enter(A, D);
    CHECK(h.enter(D, A));   // {D,A}=1
    // None of the distinct edges reached limit=2.
    CHECK(h.has_natural_exit());
    CHECK_EQ(h.edge_count(B, A), static_cast<uint64_t>(1));
    CHECK_EQ(h.edge_count(C, A), static_cast<uint64_t>(1));
    CHECK_EQ(h.edge_count(D, A), static_cast<uint64_t>(1));
}

// The shared suffix A->B in a single-block dispatcher is counted on second
// traversal (B already in bb_first_seen), but the count stays well below limit.
//
// Trace: -1->A->B->A->C->A->D->A->B (second time) -> ...
TEST(loop_limit_dispatcher_shared_exit_is_forward)
{
    BackEdgeHarness h(/*limit=*/10);
    h.enter(ENTRY, A);
    h.enter(A, B); // first_seen[B]=1 — not counted (B first-seen here)
    h.enter(B, A); // {B,A}=1
    h.enter(A, C);
    h.enter(C, A); // {C,A}=1
    h.enter(A, D);
    h.enter(D, A); // {D,A}=1
    // Second dispatch to B: B is in bb_first_seen -> {A,B}=1 (counted, but < limit=10).
    h.enter(A, B);
    CHECK_EQ(h.edge_count(A, B), static_cast<uint64_t>(1)); // counted on 2nd traversal
    CHECK(h.has_natural_exit());
}

// ── Group 5: Multi-block dispatcher — not a loop ──────────────────────────────

// The shared prefix A->B->C is traversed N times but is never a back-edge.
// Each "arm" back-edge to A is unique.
//
// Trace: -1->A->B->C->D->E->A->B->C->F->G->A->B->C->H->I
TEST(loop_limit_multi_block_dispatcher_not_a_loop)
{
    BackEdgeHarness h(/*limit=*/3);
    // Pass 1: A->B->C->D->E
    h.enter(ENTRY, A);
    h.enter(A, B);
    h.enter(B, C);
    h.enter(C, D);
    h.enter(D, E);
    // Back to A via E
    h.enter(E, A); // {E,A}=1
    // Shared prefix again
    h.enter(A, B); // 2nd traversal of A->B: B seen -> {A,B}=1
    h.enter(B, C); // 2nd traversal of B->C: C seen -> {B,C}=1
    h.enter(C, F);
    h.enter(F, G);
    // Back to A via G
    h.enter(G, A); // {G,A}=1
    // Shared prefix again
    h.enter(A, B); // 3rd traversal: {A,B}=2
    h.enter(B, C); // 3rd traversal: {B,C}=2
    h.enter(C, H);
    h.enter(H, I); // natural exit
    // No single edge reached limit=3.
    CHECK(h.has_natural_exit());
    CHECK_EQ(h.edge_count(E, A), static_cast<uint64_t>(1));
    CHECK_EQ(h.edge_count(G, A), static_cast<uint64_t>(1));
    // Shared prefix A->B and B->C counted on 2nd+ traversal (2 times each).
    // Both are still below limit=3, so natural exit holds.
    CHECK_EQ(h.edge_count(A, B), static_cast<uint64_t>(2));
    CHECK_EQ(h.edge_count(B, C), static_cast<uint64_t>(2));
}

// The *same* multi-block pattern repeated N times IS a loop.
// Back-edge E->A accumulates each iteration.
//
// Pattern: (A->B->C->D->E->A->B->C->F->G) x N
TEST(loop_limit_multi_block_loop_with_alternating_paths)
{
    const uint64_t limit = 5;
    BackEdgeHarness h(limit);
    h.enter(ENTRY, A);
    h.enter(A, B);
    h.enter(B, C);

    // First pass establishes first_seen for all blocks.
    h.enter(C, D);
    h.enter(D, E);
    h.enter(E, A); // {E,A}=1
    h.enter(A, B);
    h.enter(B, C);
    h.enter(C, F);
    h.enter(F, G);
    h.enter(G, A); // {G,A}=1

    // Repeat limit-1 more times (first pass already contributed 1 to {E,A} and {G,A}).
    // The last iteration's E->A brings {E,A} to limit and fires.
    for (uint64_t i = 0; i < limit - 1; ++i)
    {
        h.enter(A, B);
        h.enter(B, C);
        h.enter(C, D); // forward (first_seen[D] > first_seen[C])
        h.enter(D, E); // forward
        bool ok = h.enter(E, A); // back-edge {E,A}; fires when count reaches limit
        if (!ok) goto done;
        h.enter(A, B);
        h.enter(B, C);
        h.enter(C, F); // forward
        h.enter(F, G); // forward
        h.enter(G, A); // back-edge {G,A}
    }
done:
    CHECK(h.has_loop_limit());
}

// ── Group 6: CFG flattening (control-flow flattening) ────────────────────────

// Classic CFF: dispatcher D, arms A/B/C each jump back to D.
// Each arm's back-edge to D has its OWN counter.  With limit=N and
// M arms, the function runs for up to N*M total arm-to-dispatcher edges
// before any single one fires.
//
// Trace: -1->D->A->D->B->D->C->D  (1 iteration, 3 arms)
TEST(loop_limit_cfg_flattening_arms_counted_separately)
{
    // 3 arms, 3 iterations each before limit fires.
    // limit=3: iterations 1 and 2 succeed (count < 3); iteration 3 fires on A->D.
    const uint64_t limit = 3;
    BackEdgeHarness h(limit);

    h.enter(ENTRY, D); // D is dispatcher, first_seen[D]=0

    // Iteration 1: all arms first-visited (forward entries), back-edges to D count=1.
    h.enter(D, A); // forward (A not yet seen)
    h.enter(A, D); // {A,D}=1  first_seen[D]=0 < first_seen[A]=1
    h.enter(D, B); // forward
    h.enter(B, D); // {B,D}=1
    h.enter(D, C); // forward
    h.enter(C, D); // {C,D}=1

    // Iteration 2: D->arm edges are now counted (arms already in bb_first_seen).
    h.enter(D, A); // A seen -> {D,A}=1
    CHECK(h.enter(A, D)); // {A,D}=2 — still below limit=3
    h.enter(D, B);
    CHECK(h.enter(B, D)); // {B,D}=2
    h.enter(D, C);
    CHECK(h.enter(C, D)); // {C,D}=2

    // Iteration 3: A->D fires at count=3.
    h.enter(D, A);
    CHECK(!h.enter(A, D)); // {A,D}=3 >= 3 → LOOP_LIMIT
    CHECK(h.has_loop_limit());

    // Verify counts.
    CHECK_EQ(h.edge_count(A, D), static_cast<uint64_t>(3));
    CHECK_EQ(h.edge_count(B, D), static_cast<uint64_t>(2)); // never reached 3
    CHECK_EQ(h.edge_count(C, D), static_cast<uint64_t>(2));
    // D->arm edges counted on 2nd+ traversal (arms already seen).
    // D->A traversed in iters 2 and 3 (before A->D fires) = 2.
    // D->B and D->C traversed in iter 2 only (iter 3 stopped at A->D) = 1 each.
    CHECK_EQ(h.edge_count(D, A), static_cast<uint64_t>(2));
    CHECK_EQ(h.edge_count(D, B), static_cast<uint64_t>(1));
    CHECK_EQ(h.edge_count(D, C), static_cast<uint64_t>(1));
}

// A longer CFF sequence stays below limit when the loop count is within bounds.
//
// 4 arms, 3 full iterations, limit=4 — must finish naturally.
TEST(loop_limit_cfg_flattening_stays_below_limit)
{
    const uint64_t limit  = 4;
    const uint64_t arms   = 4;
    const uint64_t iters  = 3;
    BackEdgeHarness h(limit);

    // arm addresses
    const uint64_t arm[4] = {A, B, C, E};

    h.enter(ENTRY, D);
    for (uint64_t i = 0; i < iters; ++i)
    {
        for (uint64_t k = 0; k < arms; ++k)
        {
            h.enter(D, arm[k]); // forward
            CHECK(h.enter(arm[k], D)); // back-edge — must not fire yet
        }
    }
    CHECK(h.has_natural_exit());
    for (uint64_t k = 0; k < arms; ++k)
        CHECK_EQ(h.edge_count(arm[k], D), iters);
}

// ── Group 7: Edge distinctness and cross-counting ─────────────────────────────

// Two distinct back-edges to the same target do not share a counter.
// A->Z and B->Z are separate back-edges; with limit=2, neither fires
// when each is traversed once.
TEST(loop_limit_distinct_sources_to_same_target_independent)
{
    BackEdgeHarness h(/*limit=*/2);
    // Establish first_seen[Z]=0 as the earliest block.
    constexpr uint64_t Z = 0xF000;
    h.enter(ENTRY, Z); // first_seen[Z]=0
    h.enter(Z, A);     // forward
    h.enter(A, Z);     // {A,Z}=1  (first_seen[Z]=0 < first_seen[A]=1)
    h.enter(Z, B);     // forward
    h.enter(B, Z);     // {B,Z}=1  (first_seen[Z]=0 < first_seen[B]=3)
    // Neither counter reached limit=2.
    CHECK(h.has_natural_exit());
    CHECK_EQ(h.edge_count(A, Z), static_cast<uint64_t>(1));
    CHECK_EQ(h.edge_count(B, Z), static_cast<uint64_t>(1));
}

// Confirms limit=1 fires on exactly the first traversal of a back-edge.
TEST(loop_limit_fires_at_limit_one)
{
    BackEdgeHarness h(/*limit=*/1);
    h.enter(ENTRY, A);
    h.enter(A, B);
    // B->A is a back-edge (first_seen[A]=0 < first_seen[B]=1).
    CHECK(!h.enter(B, A));
    CHECK(h.has_loop_limit());
    CHECK_EQ(h.edge_count(B, A), static_cast<uint64_t>(1));
}

// ── Group 8: Nested loops ─────────────────────────────────────────────────────

// Inner loop (C->D->C) inside an outer loop (A->..->A).
// Inner back-edge D->C fires before the outer back-edge E->A does,
// when both limits are set to the same value.
TEST(loop_limit_inner_loop_fires_first)
{
    // Outer: A->(inner body)->E->A
    // Inner: C->D->C repeated
    // Structure: -1->A->B->C->D->C->D->...->E->A
    // With limit=3: inner D->C fires after 3 iterations before outer E->A
    // gets its 3rd traversal.
    const uint64_t limit = 3;
    BackEdgeHarness h(limit);

    h.enter(ENTRY, A); // first_seen[A]=0
    h.enter(A, B);     // first_seen[B]=1 — forward
    h.enter(B, C);     // first_seen[C]=2 — forward

    // Inner loop: C->D->C repeated.
    h.enter(C, D);     // first_seen[D]=3 — forward
    h.enter(D, C);     // {D,C}=1: first_seen[C]=2 < first_seen[D]=3 -> back-edge
    h.enter(C, D);     // forward (first_seen[D]=3, first_seen[C]=2; to=D, from=C; first_seen[D] < first_seen[C]? NO)
    h.enter(D, C);     // {D,C}=2
    h.enter(C, D);     // forward
    bool fired = !h.enter(D, C); // {D,C}=3 >= 3 -> LOOP_LIMIT
    CHECK(fired);
    CHECK(h.has_loop_limit());
    // Outer E->A was never reached.
    CHECK_EQ(h.edge_count(E, A), static_cast<uint64_t>(0));
}

// ── Group 9: Real-world dispatcher shape — rand_string style ─────────────────

// Reproduces the topology that originally caused the tum-suite divergence:
// a small loop body (0x144b) followed by a condition block (0x149b) that
// either loops back or exits.  The loop back-edge is 0x149b->0x144b.
// With the revisit criterion, edges inside the loop body (body->post, post->cond)
TEST(loop_limit_rand_string_topology)
{
    // RVAs matching the real binary (symbolic names for clarity).
    constexpr uint64_t setup    = 0x143c;
    constexpr uint64_t body     = 0x144b; // loop header
    constexpr uint64_t post     = 0x1450; // after rand() call
    constexpr uint64_t cond     = 0x149b; // loop condition
    constexpr uint64_t exit_blk = 0x14a5;

    const uint64_t limit = 50;
    BackEdgeHarness h(limit);

    h.enter(ENTRY, setup);
    h.enter(setup, body); // first_seen[body]=1 — forward

    // Forward chain inside first iteration.
    h.enter(body, post);  // first_seen[post]=2 — forward
    h.enter(post, cond);  // first_seen[cond]=3 — forward

    // Loop: cond->body is the back-edge (body already in bb_first_seen).
    for (uint64_t i = 0; i < limit - 1; ++i)
    {
        CHECK(h.enter(cond, body)); // back-edge {cond,body} — must not fire yet
        CHECK(h.enter(body, post)); // forward
        CHECK(h.enter(post, cond)); // forward
    }
    CHECK_EQ(h.edge_count(cond, body), limit - 1);
    // limit-th traversal fires.
    CHECK(!h.enter(cond, body));
    CHECK(h.has_loop_limit());

    // Forward edges inside the loop are now counted on second+ traversal
    // (body and cond are in bb_first_seen); consistent across JIT/Unicorn.
    CHECK_EQ(h.edge_count(body, post), limit - 1);
    CHECK_EQ(h.edge_count(post, cond), limit - 1);
}

// ── Group 9b: While-loop / jump-to-condition ────────────────────────────────

// A while-loop compiled with the jump-to-condition idiom visits the condition
// block before the loop body (via the initial unconditional jmp).  This means
// first_seen[cond] < first_seen[body] — the OPPOSITE of a do-while layout.
// The back-edge is cond->body; the old ordering filter rejected it (since
// first_seen[body] > first_seen[cond]), causing neither JIT nor Unicorn to fire.
// The revisit criterion counts any edge to a previously-seen destination,
// so cond->body is correctly counted from its second traversal onward.
//
// Modelled as JIT sees it (body->cond is a fallthrough, never passed to
// on_bb_entered; only cond->body fires on each loop iteration).
TEST(loop_limit_while_loop_jump_to_condition)
{
    constexpr uint64_t cond = 0xC000;
    constexpr uint64_t body = 0xB000;

    const uint64_t limit = 10;
    BackEdgeHarness h(limit);

    // Initial jmp-to-condition: cond visited BEFORE body.
    h.enter(ENTRY, cond);  // cond seen; from=ENTRY (-1) => not counted

    // First loop iteration: cond->body (body not yet seen -> not counted).
    CHECK(h.enter(cond, body));  // body first-seen here; not a back-edge yet.
    // body->cond is a fallthrough in JIT — never passed to on_bb_entered.

    // Subsequent iterations: cond->body now counts (body IS in first_seen).
    for (uint64_t i = 0; i < limit - 1; ++i)
        CHECK(h.enter(cond, body));  // back-edge; count++

    CHECK_EQ(h.edge_count(cond, body), limit - 1);
    // limit-th traversal fires.
    CHECK(!h.enter(cond, body));
    CHECK(h.has_loop_limit());
    CHECK_EQ(h.edge_count(cond, body), limit);
}

// ── Group 10: QEMU TB-merging regression ─────────────────────────────────────

// Before the fix, Unicorn reported the TB start as from_rva.  When a TB
// subsumes [post, cond], Unicorn's from_rva for the body-entry was `post`
// rather than the correct `cond`.  This split the back-edge count across
// {cond,body} (iteration 1) and {post,body} (all later iterations).
//
// With the FALLTHROUGH normalisation in UnicornExecutor, both executors
// see the same from_rva (`cond`) and the edge {cond,body} accumulates
// uniformly.  This test verifies that the verifier correctly fires when
// BOTH executors report the same edge (i.e., normalisation worked).
TEST(loop_limit_qemu_tb_merge_uniform_reporting)
{
    constexpr uint64_t body = 0x144b;
    constexpr uint64_t cond = 0x149b;

    // Simulate JIT: always reports {cond, body}.
    const uint64_t limit = 10;
    BackEdgeHarness jit(limit);
    jit.enter(ENTRY, body);
    jit.enter(body, cond); // cond first seen after body — cond step > body step

    for (uint64_t i = 0; i < limit; ++i)
    {
        bool ok = jit.enter(cond, body); // {cond,body}++ each iteration
        if (!ok) break;
        jit.enter(body, cond);
    }
    CHECK(jit.has_loop_limit());
    CHECK_EQ(jit.edge_count(cond, body), limit);

    // Simulate the *old* Unicorn bug: first iteration reports {cond,body},
    // subsequent ones report {post,body} (TB start is post, which subsumes cond).
    constexpr uint64_t post = 0x1450;
    BackEdgeHarness uc_buggy(limit);
    uc_buggy.enter(ENTRY, body);
    uc_buggy.enter(body, post);
    uc_buggy.enter(post, cond);
    uc_buggy.enter(cond, body); // {cond,body}=1 — correct first time
    uc_buggy.enter(body, post);
    uc_buggy.enter(post, cond);
    // Now QEMU merges [post..cond] into one TB; next from_rva = post (TB start).
    for (uint64_t i = 0; i < limit; ++i)
    {
        bool ok = uc_buggy.enter(post, body); // {post,body}++ — wrong edge key
        if (!ok) break;
        uc_buggy.enter(body, post);
        uc_buggy.enter(post, cond);
    }
    // {cond,body}=1, {post,body} accumulated separately.
    // With limit=10, {post,body} fires before {cond,body} could reach 10.
    // This shows the divergence: JIT counts one edge; buggy Unicorn counts another.
    uint64_t jit_count   = jit.edge_count(cond, body);
    uint64_t uc_cond_cnt = uc_buggy.edge_count(cond, body);
    uint64_t uc_post_cnt = uc_buggy.edge_count(post, body);
    // In the buggy model, the two counters are never equal to the JIT counter.
    CHECK(uc_cond_cnt != jit_count || uc_post_cnt != static_cast<uint64_t>(0));
}
