#pragma once
#include "ir_mutation.hpp"
#include "mutation_operators.hpp" // for CategorizedMutation
#include <cstdint>
#include <optional>
#include <string>

namespace lifted::fault_injection {

struct MutationPoint {
    std::string func_name;           // name of the function being mutated
    size_t instruction_index;        // 0-based flat index within function (stable across CloneModule)
    std::string instruction_str;     // IR text of original instruction (for reports)
    unsigned instruction_width_bits; // bit width of result type (1, 8, 32, 64, etc.)
    std::optional<uint64_t> bb_rva;  // native BB RVA if recoverable (currently nullopt - lost after inlining)
    const CategorizedMutation *mut;  // non-owning pointer into all_integer_operators() table
};

} // namespace lifted::fault_injection
