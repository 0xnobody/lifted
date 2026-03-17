#pragma once
#include <string_view>

namespace lifted::fault_injection {

enum class MutationCategory {
    ARITHMETIC,
    BITWISE,
    COMPARISON_NEG,
    COMPARISON_BDRY,
    OPERAND_SWAP,
    DROP_COMPUTATION,
    CONSTANT_REPL,
    NEGATE_TRUNC,
};

enum class difficulty_t { EASY, MEDIUM, HARD };

constexpr difficulty_t static_difficulty(MutationCategory cat) {
    switch (cat) {
    case MutationCategory::ARITHMETIC:
    case MutationCategory::CONSTANT_REPL:
        return difficulty_t::EASY;
    case MutationCategory::COMPARISON_BDRY:
        return difficulty_t::HARD;
    default:
        return difficulty_t::MEDIUM;
    }
}

constexpr std::string_view category_name(MutationCategory cat) {
    switch (cat) {
    case MutationCategory::ARITHMETIC:       return "ARITHMETIC";
    case MutationCategory::BITWISE:          return "BITWISE";
    case MutationCategory::COMPARISON_NEG:   return "COMPARISON_NEG";
    case MutationCategory::COMPARISON_BDRY:  return "COMPARISON_BDRY";
    case MutationCategory::OPERAND_SWAP:     return "OPERAND_SWAP";
    case MutationCategory::DROP_COMPUTATION: return "DROP_COMPUTATION";
    case MutationCategory::CONSTANT_REPL:    return "CONSTANT_REPL";
    case MutationCategory::NEGATE_TRUNC:     return "NEGATE_TRUNC";
    }
    return "UNKNOWN";
}

constexpr std::string_view difficulty_name(difficulty_t d) {
    switch (d) {
    case difficulty_t::EASY:   return "EASY";
    case difficulty_t::MEDIUM: return "MEDIUM";
    case difficulty_t::HARD:   return "HARD";
    }
    return "UNKNOWN";
}

} // namespace lifted::fault_injection
