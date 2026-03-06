#pragma once

#include "cfg_data.hpp"
#include "cfg_dot.hpp"
#include "pipeline/pipeline.hpp"

#include <string>
#include <unordered_map>

namespace lifted::visualization {

struct OverlayOptions {
    CfgDotOptions cfg_opts         = {};    ///< Base CFG formatting
    bool          show_hit_counts  = true;  ///< Show block execution counts
    bool          show_divergence  = true;  ///< Highlight divergence location
    bool          show_trace_path  = true;  ///< Highlight path to divergence
    bool          show_escapes     = true;  ///< Show escaped/missing blocks
    bool          show_loop_counts = true;  ///< Annotate back-edge iteration counts
};

struct OverlayData {
    /// Aggregate hit counts (rva -> total hits across all runs).
    /// Typically from PipelineReport::src_block_hits.
    const std::unordered_map<uint64_t, uint64_t> *block_hits = nullptr;

    /// Optional: a specific divergent run to highlight.
    const pipeline::RunOutcome *divergence = nullptr;
};

/// Generate DOT string for a CFG with pipeline execution data overlaid.
std::string overlay_to_dot(const CfgSnapshot    &cfg,
                            const OverlayData    &data,
                            const OverlayOptions &opts = {});

} // namespace lifted::visualization
