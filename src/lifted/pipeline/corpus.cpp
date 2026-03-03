#include "corpus.hpp"

namespace lifted::pipeline {

// ── Corpus ───────────────────────────────────────────────────────────────────

void Corpus::add_if_interesting(CorpusEntry entry, const corpus_classifier_t &classifier)
{
    // Run classifier BEFORE updating coverage so it sees the pre-entry coverage
    // state.  This makes coverage-guided decisions accurate for the current entry.
    bool accept = classifier(entry, *this);

    // Update coverage *after* the classifier so that subsequent entries within
    // the same stage see a fresh picture (even if this entry was rejected).
    for (uint64_t rva : entry.bb_trace)
        covered_bbs_.insert(rva);

    if (accept)
        entries_.push_back(std::move(entry));
}

bool Corpus::has_new_coverage(const std::vector<uint64_t> &trace) const
{
    for (uint64_t rva : trace)
        if (!covered_bbs_.count(rva))
            return true;
    return false;
}

// ── Built-in classifiers ─────────────────────────────────────────────────────

corpus_classifier_t make_natural_exit_classifier()
{
    return [](const CorpusEntry &entry, const Corpus &) -> bool {
        return entry.exit_reason == verification::exit_type::NATURAL_EXIT;
    };
}

corpus_classifier_t make_coverage_guided_classifier()
{
    return [](const CorpusEntry &entry, const Corpus &corpus) -> bool {
        return corpus.has_new_coverage(entry.bb_trace);
    };
}

corpus_classifier_t make_combined_classifier()
{
    return [](const CorpusEntry &entry, const Corpus &corpus) -> bool {
        return entry.exit_reason == verification::exit_type::NATURAL_EXIT ||
               corpus.has_new_coverage(entry.bb_trace);
    };
}

} // namespace lifted::pipeline
