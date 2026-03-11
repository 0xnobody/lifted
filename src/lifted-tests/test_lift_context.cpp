#include "test_framework.hpp"

#include "lifter/lift_context.hpp"

TEST(lift_context_remap_synthetic_sources_moves_split_owned_indices)
{
    using namespace lifted::lifter;

    lift_context_t ctx;

    constexpr bb_id_t original_source = 0x116b;
    constexpr bb_id_t split_second_half = 0x117a;
    constexpr bb_id_t unrelated_source = 0x2200;
    constexpr bb_id_t external_synth = 0xFFFF000000000000ULL;
    constexpr bb_id_t indirect_synth = 0xFFFF000000000001ULL;
    constexpr bb_id_t recursive_synth = 0xFFFF000000000002ULL;
    constexpr bb_id_t unrelated_external_synth = 0xFFFF000000000003ULL;

    ctx.external_synthetic_index[{original_source, 0x1050}] = external_synth;
    ctx.external_synthetic_index[{unrelated_source, 0x1060}] = unrelated_external_synth;
    ctx.indirect_synthetic_index[original_source] = indirect_synth;
    ctx.recursive_synthetic_index[original_source] = recursive_synth;

    ctx.remap_synthetic_sources(original_source, split_second_half);

    CHECK_EQ(ctx.external_synthetic_index.count({original_source, 0x1050}), 0U);
    CHECK_EQ(ctx.external_synthetic_index.count({split_second_half, 0x1050}), 1U);
    CHECK_EQ(ctx.external_synthetic_index.at({split_second_half, 0x1050}), external_synth);

    CHECK_EQ(ctx.indirect_synthetic_index.count(original_source), 0U);
    CHECK_EQ(ctx.indirect_synthetic_index.count(split_second_half), 1U);
    CHECK_EQ(ctx.indirect_synthetic_index.at(split_second_half), indirect_synth);

    CHECK_EQ(ctx.recursive_synthetic_index.count(original_source), 0U);
    CHECK_EQ(ctx.recursive_synthetic_index.count(split_second_half), 1U);
    CHECK_EQ(ctx.recursive_synthetic_index.at(split_second_half), recursive_synth);

    CHECK_EQ(ctx.external_synthetic_index.count({unrelated_source, 0x1060}), 1U);
    CHECK_EQ(ctx.external_synthetic_index.at({unrelated_source, 0x1060}), unrelated_external_synth);
}
