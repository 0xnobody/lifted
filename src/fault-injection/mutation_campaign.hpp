#pragma once

#include "mutation_point.hpp"

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace lifted::fault_injection {

enum class MutantStatus { KILLED, SURVIVED, EQUIVALENT, ERROR };

struct MutantResult {
    MutationPoint point;
    MutantStatus status    = MutantStatus::ERROR;
    size_t runs_killed     = 0;  // pipeline stages that reported FAIL_DIVERGED
    size_t runs_total      = 0;  // total pipeline stages run
    int    stage_killed    = -1; // 0-based index of first stage with FAIL_DIVERGED, -1=never
    std::string mutated_str;     // IR text of the instruction after mutation applied

    double kill_rate() const;
    double empirical_difficulty() const; // 1.0 - kill_rate()
};

struct MutationReport {
    std::string func_name;
    std::string binary_stem;

    size_t total_enumerated = 0; // all (instruction, op) pairs before sampling
    size_t total_mutants    = 0; // sampled and tested
    size_t budget_requested = 0; // config budget (for display only)
    size_t killed           = 0;
    size_t survived         = 0;
    size_t equivalent       = 0; // no observable behavioral difference
    size_t errors           = 0;

    std::vector<MutantResult> results;

    double mutation_score() const; // killed / total_mutants
    double adjusted_score() const; // killed / (total_mutants - equivalent)

    // Per-category, per-difficulty, per-width breakdowns — {killed, total}
    std::map<MutationCategory, std::pair<size_t, size_t>> by_category;
    std::map<difficulty_t, std::pair<size_t, size_t>> by_difficulty;
    std::map<unsigned, std::pair<size_t, size_t>> by_width_bits;

    // Timing fields populated by the eval-suite campaign runner.
    double lift_duration_ms     = 0.0;
    double campaign_duration_ms = 0.0;

    void print(std::ostream &os) const;
};

struct MutationCampaignConfig {
    size_t budget;
    uint64_t seed;
    std::vector<MutationCategory> filter_categories; // empty = all categories

    // Explicit constructor required to work around GCC 11 nested-class
    // default-member-initializer limitation (CWG 1607).
    MutationCampaignConfig() : budget(200), seed(0x1337) {}
};

} // namespace lifted::fault_injection
