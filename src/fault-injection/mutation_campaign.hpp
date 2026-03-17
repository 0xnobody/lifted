#pragma once
#include "ir_mutation.hpp"
#include "mutation_point.hpp"
#include <filesystem>
#include <iosfwd>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>
#include <map>
#include <optional>
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
    std::string   mutated_str;   // IR text of the instruction after mutation applied

    double kill_rate() const;
    double empirical_difficulty() const; // 1.0 - kill_rate()
};

struct MutationReport {
    std::string func_name;
    std::string binary_stem;

    size_t total_enumerated  = 0; // all (instruction, op) pairs before sampling
    size_t total_mutants     = 0; // sampled and tested
    size_t budget_requested  = 0; // cfg.budget (for display only)
    size_t killed           = 0;
    size_t survived         = 0;
    size_t equivalent       = 0; // FAIL_INCOMPARABLE: no observable behavioral difference
    size_t errors           = 0;

    std::vector<MutantResult> results;

    double mutation_score() const;  // killed / total_mutants
    double adjusted_score() const;  // killed / (total_mutants - equivalent)

    // Per-category, per-difficulty, per-width breakdowns — {killed, total}
    std::map<MutationCategory, std::pair<size_t, size_t>> by_category;
    std::map<difficulty_t,     std::pair<size_t, size_t>> by_difficulty;
    std::map<unsigned,         std::pair<size_t, size_t>> by_width_bits;

    void print(std::ostream &os) const;
};

class MutationCampaign {
public:
    struct Config {
        size_t   budget;
        uint64_t seed;
        std::vector<MutationCategory> filter_categories; // empty = all categories

        // Explicit constructor required to work around GCC 11 nested-class
        // default-member-initializer limitation (CWG 1607).
        Config() : budget(200), seed(0x1337) {}
    };

    // Main entry point.
    // Lifts the function at entry_rva from the binary, applies always_inline,
    // runs a baseline (must PASS), then tests each sampled mutant.
    // Returns a MutationReport on success, or an Error if lifting/baseline fails.
    static llvm::Expected<MutationReport> run(
        llvm::LLVMContext             &ctx,
        const std::filesystem::path   &binary_path,
        const std::string             &func_name,
        uint64_t                       entry_rva,
        Config                         cfg = Config());
};

} // namespace lifted::fault_injection
