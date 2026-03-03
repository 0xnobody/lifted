#pragma once

#include "run_config.hpp"
#include "../verification/verifier_state.hpp" // exit_type

#include <cstdint>
#include <functional>
#include <set>
#include <vector>

namespace lifted::pipeline {

// ── CorpusEntry ──────────────────────────────────────────────────────────────

struct CorpusEntry
{
    RunConfig config;

    /// Why the src run terminated.
    verification::exit_type exit_reason;

    /// Ordered sequence of basic block RVAs entered during the src run.
    std::vector<uint64_t> bb_trace;

    /// Ordinal of this run within its producing stage (0-based).
    uint64_t run_index;
};

// ── Corpus (forward declaration for classifier type) ─────────────────────────

class Corpus;

// ── corpus_classifier_t ───────────────────────────────────────────────────────
// Predicate deciding whether a CorpusEntry should be added.
// 'corpus' is the current corpus state — enables coverage-guided decisions.

using corpus_classifier_t =
    std::function<bool(const CorpusEntry &entry, const Corpus &corpus)>;

// ── Built-in classifiers ─────────────────────────────────────────────────────

/// Accept only runs that reached a natural exit.
corpus_classifier_t make_natural_exit_classifier();

/// Accept only runs that cover at least one previously-unseen basic block.
corpus_classifier_t make_coverage_guided_classifier();

/// Accept if NATURAL_EXIT or new coverage — whichever fires first (default).
corpus_classifier_t make_combined_classifier();

// ── Corpus ───────────────────────────────────────────────────────────────────

class Corpus
{
public:
    /// Conditionally add entry if the classifier returns true.
    /// Updates covered_bbs_ regardless of classifier outcome so that
    /// sequential runs within the same stage see fresh coverage data.
    void add_if_interesting(CorpusEntry entry, const corpus_classifier_t &classifier);

    /// True iff any RVA in 'trace' has not yet been seen by this corpus.
    bool has_new_coverage(const std::vector<uint64_t> &trace) const;

    const std::vector<CorpusEntry> &entries() const { return entries_; }
    size_t size() const { return entries_.size(); }
    size_t unique_blocks_covered() const { return covered_bbs_.size(); }

private:
    std::vector<CorpusEntry> entries_;
    std::set<uint64_t>       covered_bbs_;
};

} // namespace lifted::pipeline
