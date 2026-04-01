#include "mutation_campaign.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <ostream>

namespace lifted::fault_injection
{

double MutantResult::kill_rate() const
{
    if (runs_total == 0)
        return 0.0;
    return static_cast<double>(runs_killed) / static_cast<double>(runs_total);
}

double MutantResult::empirical_difficulty() const
{
    return 1.0 - kill_rate();
}

double MutationReport::mutation_score() const
{
    if (total_mutants == 0)
        return 0.0;
    return static_cast<double>(killed) / static_cast<double>(total_mutants);
}

double MutationReport::adjusted_score() const
{
    if (total_mutants <= equivalent)
        return 0.0;
    return static_cast<double>(killed) / static_cast<double>(total_mutants - equivalent);
}

void MutationReport::print(std::ostream &os) const
{
    auto pct = [](size_t num, size_t den) -> double
    {
        if (den == 0)
            return 0.0;
        return 100.0 * static_cast<double>(num) / static_cast<double>(den);
    };

    os << "=== MUTATION REPORT: " << func_name << " ===\n";
    os << "Binary: " << binary_stem << "\n";
    os << "Pipeline: optimized baseline vs optimized mutant\n";
    os << "Enumerated: " << total_enumerated << " mutation points"
       << "  |  Tested: " << total_mutants << " (budget: " << budget_requested << ")\n";
    os << "Killed: " << killed
       << "  |  Survived: " << survived
       << "  |  Equivalent: " << equivalent
       << "  |  Errors: " << errors << "\n";
    os << std::fixed << std::setprecision(1);
    os << "Mutation Score: " << pct(killed, total_mutants) << "%"
       << "  (adjusted: " << pct(killed, total_mutants - equivalent) << "%)\n";

    os << "\nBy Category:\n";
    constexpr MutationCategory all_cats[] = {
        MutationCategory::ARITHMETIC,
        MutationCategory::BITWISE,
        MutationCategory::COMPARISON_NEG,
        MutationCategory::COMPARISON_BDRY,
        MutationCategory::OPERAND_SWAP,
        MutationCategory::DROP_COMPUTATION,
        MutationCategory::CONSTANT_REPL,
        MutationCategory::NEGATE_TRUNC,
    };
    for (auto cat : all_cats)
    {
        auto it = by_category.find(cat);
        if (it == by_category.end() || it->second.second == 0)
            continue;
        auto [k, t] = it->second;
        auto diff = static_difficulty(cat);
        std::string_view diff_name =
            diff == difficulty_t::EASY ? "EASY" : diff == difficulty_t::MEDIUM ? "MEDIUM"
                                                                               : "HARD";
        os << "  " << std::left << std::setw(20) << category_name(cat)
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)"
           << "  [" << diff_name << "]\n";
    }

    os << "\nBy Difficulty:\n";
    constexpr difficulty_t all_diffs[] = {
        difficulty_t::EASY, difficulty_t::MEDIUM, difficulty_t::HARD};
    for (auto d : all_diffs)
    {
        auto it = by_difficulty.find(d);
        if (it == by_difficulty.end() || it->second.second == 0)
            continue;
        auto [k, t] = it->second;
        std::string_view dname =
            d == difficulty_t::EASY ? "EASY" : d == difficulty_t::MEDIUM ? "MEDIUM"
                                                                         : "HARD";
        os << "  " << std::left << std::setw(8) << dname
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)\n";
    }

    os << "\nBy Width (instruction operand bit width):\n";
    constexpr unsigned ordered_widths[] = {64, 32, 16, 8, 1};
    for (unsigned w : ordered_widths)
    {
        auto it = by_width_bits.find(w);
        if (it == by_width_bits.end() || it->second.second == 0)
            continue;
        auto [k, t] = it->second;
        std::string label = "i" + std::to_string(w);
        std::string annot = (w == 8 || w == 1) ? " [flag comp.]" : "";
        os << "  " << std::left << std::setw(6) << label
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)" << annot << "\n";
    }
    for (const auto &[w, kt] : by_width_bits)
    {
        bool is_ordered = false;
        for (unsigned ow : ordered_widths)
        {
            if (ow == w)
            {
                is_ordered = true;
                break;
            }
        }
        if (is_ordered || kt.second == 0)
            continue;
        auto [k, t] = kt;
        std::string label = "i" + std::to_string(w);
        os << "  " << std::left << std::setw(6) << label
           << "killed " << k << "/" << t
           << "  (" << pct(k, t) << "%)  [other]\n";
    }

    os << "\nSurvivors:\n";
    bool any_survivors = false;
    for (const auto &r : results)
    {
        if (r.status != MutantStatus::SURVIVED && r.status != MutantStatus::EQUIVALENT)
            continue;
        any_survivors = true;
        os << "  [" << category_name(r.point.mut->category) << "] "
           << r.point.mut->name << "  (i" << r.point.instruction_width_bits << ")\n";
        os << "    before: " << r.point.instruction_str << "\n";
        os << "    after:  " << r.mutated_str << "\n";
    }
    if (!any_survivors)
        os << "  (none)\n";
}

} // namespace lifted::fault_injection
