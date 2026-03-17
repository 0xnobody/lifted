#pragma once
#include "mutation_point.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace llvm { class Function; }

namespace lifted::fault_injection {

struct EnumerationConfig {
    size_t budget   = 200;    // max mutation points to sample
    uint64_t seed   = 0x1337; // RNG seed for reproducibility
    // Empty = all categories allowed. Non-empty = only listed categories.
    std::vector<MutationCategory> allowed_categories;
};

// Enumerate all valid (instruction, operator) pairs in F, then apply
// operator-proportional sampling down to cfg.budget.
// F must already have always_inline applied.
// out_total_enumerated: if non-null, set to the total count before sampling.
std::vector<MutationPoint>
enumerate_and_sample(llvm::Function &F,
                     const std::vector<CategorizedMutation> &operators,
                     const EnumerationConfig &cfg = {},
                     size_t *out_total_enumerated = nullptr);

// Walk function F to find the instruction at flat 0-based index idx.
// Returns nullptr if idx is out of range.
llvm::Instruction *get_instruction_at(llvm::Function *F, size_t idx);

// Get the flat 0-based index of instruction I within its function.
// Returns SIZE_MAX if not found.
size_t get_instruction_index(llvm::Function *F, llvm::Instruction *I);

} // namespace lifted::fault_injection
