#pragma once

#include "../verification/comparator.hpp"
#include "run_config.hpp"

#include <iosfwd>
#include <memory>
#include <string>

namespace lifted::pipeline {

// ── DeepDiveConfig ────────────────────────────────────────────────────────────
//
// Parameters controlling a deep-dive re-run.  Passed to Pipeline::deep_dive().

struct DeepDiveConfig
{
    // How many checkpoint events before/after the first divergence to include
    // in the printed output.  0 means show all events (the default).
    size_t pre_context  = 0;
    size_t post_context = 0;
};

// ── DeepDiveResult ────────────────────────────────────────────────────────────
//
// Return value of Pipeline::deep_dive().  Contains the re-run results and
// comparison, plus a print() method for a side-by-side chronological display.

struct DeepDiveResult
{
    std::string src_name;  // from Executor::name() — e.g. "JIT"
    std::string tgt_name;  // from Executor::name() — e.g. "Unicorn"

    RunConfig                         used_config;  // the replayed RunConfig
    verification::run_result_t        src_result;
    verification::run_result_t        tgt_result;
    verification::comparison_result_t comparison;

    // Context window passed from DeepDiveConfig.  Stored here so print() is
    // self-contained and does not need the config at call time.
    size_t pre_context  = 0;
    size_t post_context = 0;

    // Print a side-by-side chronological event trace to os.
    //
    // For each checkpoint event index i, the src and tgt detail records are
    // displayed.  Events before the first divergence are shown in a compact
    // shared form; events at or after the divergence show both sides in full.
    //
    // pre_context / post_context control how many events around the first
    // divergence are shown (0 = show everything).
    void print(std::ostream &os) const;
};

} // namespace lifted::pipeline
