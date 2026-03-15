#include "test_framework.hpp"
#include "pipeline/pipeline.hpp"
#include "visualization/cfg_dot.hpp"
#include "visualization/pipeline_overlay.hpp"

#include <llvm/ADT/AddressRanges.h>
#include <remill/Arch/X86/Runtime/State.h>

using namespace lifted;
using namespace lifted::pipeline;
using namespace lifted::verification;
using namespace lifted::visualization;

namespace {


run_result_t make_result(exit_type et = exit_type::NATURAL_EXIT)
{
    run_result_t r{};
    r.exit_reason = et;
    r.checkpoint_record.sync_on = event_flags::DEFAULT;
    r.checkpoint_record.compare_dims = compare_dimension_flags::DEFAULT;
    return r;
}

lifter::lifted_bb_t real_block(lifter::bb_id_t                    id,
                               uint64_t                           start,
                               uint64_t                           end,
                               remill::Instruction::Category      term = remill::Instruction::Category::kCategoryNormal)
{
    return lifter::lifted_bb_t{
        .type = lifter::lifted_bb_t::Type::REAL,
        .id = id,
        .func_name = "fn",
        .rva_range = llvm::AddressRange(start, end),
        .terminating_category = term,
        .static_target_rva = std::nullopt,
        .static_continuation_rva = std::nullopt,
        .was_truncated_by_stop = false,
    };

}

lifter::lifted_bb_t synthetic_block(lifter::bb_id_t id)
{
    return lifter::lifted_bb_t{
        .type = lifter::lifted_bb_t::Type::SYNTHETIC,
        .id = id,
        .func_name = "fn",
        .rva_range = std::nullopt,
        .terminating_category = std::nullopt,
        .static_target_rva = std::nullopt,
        .static_continuation_rva = std::nullopt,
        .was_truncated_by_stop = false,
    };
}

} // namespace

TEST(overlay_highlights_target_only_divergence_by_containment)
{
    CfgSnapshot cfg{};
    cfg.entry_rva = 0x1000;
    cfg.basic_blocks.insert(real_block(1, 0x1000, 0x1010));
    cfg.basic_blocks.insert(real_block(2, 0x1010, 0x1020));
    cfg.edges.insert(lifter::edge_t{1, 2, lifter::edge_t::Type::CONTROL_FLOW});

    RunOutcome outcome{};
    outcome.src_result = make_result();
    outcome.src_result.bb_trace = {0x1000};
    outcome.tgt_result = make_result();
    outcome.comparison.status = comparison_status::FAIL_DIVERGED;
    outcome.diff.emplace();
    outcome.diff->bb_trace_diff = bb_trace_diff_t{
        .len_r1 = 1,
        .len_r2 = 2,
        .entries = {{
            .index = 1,
            .rva_r1 = std::nullopt,
            .rva_r2 = 0x1014,
        }},
    };

    OverlayOptions opts{};
    opts.show_hit_counts = false;
    std::string dot = overlay_to_dot(cfg, OverlayData{.divergence = &outcome}, opts);
    CHECK(dot.find("0x1010..0x1020 | NORM | DIVERGED") != std::string::npos);
}

TEST(overlay_falls_back_to_checkpoint_context_window)
{
    CfgSnapshot cfg{};
    cfg.entry_rva = 0x1000;
    cfg.basic_blocks.insert(real_block(1, 0x1000, 0x1010));
    cfg.basic_blocks.insert(real_block(2, 0x1010, 0x1020));
    cfg.basic_blocks.insert(real_block(3, 0x1020, 0x1030));

    RunOutcome outcome{};
    outcome.src_result = make_result();
    outcome.tgt_result = make_result();
    outcome.comparison.status = comparison_status::FAIL_DIVERGED;
    outcome.comparison.first_checkpoint_divergence = checkpoint_divergence_t{
        .index = 5,
        .field = checkpoint_field::STATE,
    };
    outcome.diff.emplace();
    outcome.diff->checkpoint_diff = checkpoint_diff_t{
        .len_r1 = 5,
        .len_r2 = 5,
        .entries = {{
            .index = 5,
            .first_diverging_field = checkpoint_field::STATE,
            .cp_r1 = checkpoint_t{},
            .cp_r2 = checkpoint_t{},
            .preceding_bbs = {0x1000, 0x1014, 0x9999},
            .diverging_event_is_bb = false,
        }},
    };
    OverlayOptions opts{};
    opts.show_hit_counts = false;
    std::string dot = overlay_to_dot(cfg, OverlayData{.divergence = &outcome}, opts);
    CHECK(dot.find("0x1010..0x1020 | NORM | DIVERGED") != std::string::npos);
}

TEST(cfg_to_dot_marks_call_target_kinds_with_merge_synthetic)
{
    using Cat = remill::Instruction::Category;

    CfgSnapshot cfg{};
    cfg.entry_rva = 0x1000;
    cfg.basic_blocks.insert(real_block(1, 0x1000, 0x1004, Cat::kCategoryDirectFunctionCall));
    cfg.basic_blocks.insert(real_block(2, 0x1010, 0x1014, Cat::kCategoryDirectFunctionCall));
    cfg.basic_blocks.insert(real_block(3, 0x1020, 0x1024, Cat::kCategoryDirectFunctionCall));
    cfg.basic_blocks.insert(real_block(4, 0x1030, 0x1034, Cat::kCategoryIndirectFunctionCall));
    cfg.basic_blocks.insert(synthetic_block(20));
    cfg.basic_blocks.insert(synthetic_block(21));
    cfg.basic_blocks.insert(synthetic_block(22));

    cfg.edges.insert(lifter::edge_t{2, 20, lifter::edge_t::Type::SYNTHETIC_EXTERNAL});
    cfg.edges.insert(lifter::edge_t{3, 21, lifter::edge_t::Type::SYNTHETIC_RECURSIVE_CALL});
    cfg.edges.insert(lifter::edge_t{4, 22, lifter::edge_t::Type::SYNTHETIC_INDIRECT});

    cfg.synthetic_blocks.emplace(20, SyntheticBlockSnapshot{
        .type = lifter::synthetic_block_info_t::Type::EXTERNAL,
        .dest_addr = 0x401000,
        .annotation_name = "puts",
    });
    cfg.synthetic_blocks.emplace(21, SyntheticBlockSnapshot{
        .type = lifter::synthetic_block_info_t::Type::RECURSIVE,
        .dest_addr = 0x1020,
        .annotation_name = {},
    });
    cfg.synthetic_blocks.emplace(22, SyntheticBlockSnapshot{
        .type = lifter::synthetic_block_info_t::Type::INDIRECT,
        .dest_addr = std::nullopt,
        .annotation_name = {},
    });

    CfgDotOptions dot_opts{};
    dot_opts.merge_synthetic = true;
    std::string dot = cfg_to_dot(cfg, dot_opts);
    CHECK(dot.find("0x1000..0x1004 | CALL:int") != std::string::npos);
    CHECK(dot.find("0x1010..0x1014 | CALL:ext | → puts()") != std::string::npos);
    CHECK(dot.find("0x1020..0x1024 | CALL:rec | → recursive()") != std::string::npos);
    CHECK(dot.find("0x1030..0x1034 | ICALL:ind | → indirect()") != std::string::npos);
}
