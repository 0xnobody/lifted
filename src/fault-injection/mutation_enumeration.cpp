#include "mutation_enumeration.hpp"
#include "mutation_operators.hpp"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <map>
#include <numeric>
#include <random>
#include <unordered_set>

namespace lifted::fault_injection
{

llvm::Instruction *get_instruction_at(llvm::Function *F, size_t idx)
{
    size_t i = 0;
    for (auto &BB : *F)
        for (auto &I : BB)
            if (i++ == idx)
                return &I;
    return nullptr;
}

size_t get_instruction_index(llvm::Function *F, llvm::Instruction *I)
{
    size_t i = 0;
    for (auto &BB : *F)
        for (auto &inst : BB)
        {
            if (&inst == I)
                return i;
            ++i;
        }
    return SIZE_MAX;
}

std::vector<MutationPoint>
enumerate_and_sample(llvm::Function &F,
                     const std::vector<CategorizedMutation> &operators,
                     const EnumerationConfig &cfg,
                     size_t *out_total_enumerated)
{

    // Build a fast lookup set for allowed categories (empty = all allowed).
    std::unordered_set<int> allowed_set;
    for (auto cat : cfg.allowed_categories)
        allowed_set.insert(static_cast<int>(cat));
    const bool filter_cats = !cfg.allowed_categories.empty();

    // Phase 0: enumerate all valid (instruction, operator) pairs.
    // groups[op_idx] holds all MutationPoints applicable to that operator.
    std::map<size_t, std::vector<MutationPoint>> groups;

    size_t instr_idx = 0;
    for (auto &BB : F)
    {
        for (auto &I : BB)
        {
            // Compute instruction_str by printing the LLVM IR then stripping
            // leading whitespace (LLVM indents instructions with tabs/spaces).
            std::string instruction_str;
            {
                llvm::raw_string_ostream ss(instruction_str);
                I.print(ss);
                ss.flush();
                // Strip leading whitespace.
                const auto first = instruction_str.find_first_not_of(" \t");
                if (first != std::string::npos)
                    instruction_str = instruction_str.substr(first);
            }

            // instruction_width_bits: for ICmpInst use operand width (result
            // is always i1 but the comparison operates on the operand type).
            unsigned width;
            if (auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(&I))
                width = cmp->getOperand(0)->getType()->isIntegerTy()
                            ? cmp->getOperand(0)->getType()->getIntegerBitWidth()
                            : 1u;
            else
                width = I.getType()->isIntegerTy()
                            ? I.getType()->getIntegerBitWidth()
                            : 0u;

            for (size_t op_idx = 0; op_idx < operators.size(); ++op_idx)
            {
                const CategorizedMutation &cm = operators[op_idx];

                // Category filter.
                if (filter_cats &&
                    !allowed_set.count(static_cast<int>(cm.category)))
                    continue;

                if (!cm.op->can_mutate(&I))
                    continue;

                groups[op_idx].push_back(MutationPoint{
                    .func_name = std::string(F.getName()),
                    .instruction_index = instr_idx,
                    .instruction_str = instruction_str,
                    .instruction_width_bits = width,
                    .bb_rva = std::nullopt,
                    .mut = &cm,
                });
            }

            ++instr_idx;
        }
    }

    // Count total enumerated points.
    size_t total = 0;
    for (auto &[_, pts] : groups)
        total += pts.size();
    if (out_total_enumerated)
        *out_total_enumerated = total;

    // Fast path: no operators matched anything.
    if (groups.empty())
        return {};

    // Fast path: everything fits within budget.
    if (total <= cfg.budget)
    {
        std::vector<MutationPoint> all;
        all.reserve(total);
        for (auto &[_, pts] : groups)
            for (auto &p : pts)
                all.push_back(p);
        return all;
    }

    // Operator-proportional sampling.
    // active_ops: sorted by op_idx (deterministic because std::map iterates
    // in ascending key order — we just collect refs in order).
    std::mt19937_64 rng(cfg.seed);

    // Phase 1: sample min(per_op, group.size()) from each operator group.
    const size_t n_active = groups.size();
    const size_t per_op = std::max(size_t{1}, cfg.budget / n_active);

    std::vector<MutationPoint> selected;
    selected.reserve(cfg.budget);

    // Track which points were NOT selected so Phase 2 can fill the budget.
    std::vector<MutationPoint> unselected;
    unselected.reserve(total);

    for (auto &[op_idx, pts] : groups)
    {
        // Work on a shuffled copy so we can split selected vs unselected.
        std::vector<MutationPoint> shuffled = pts;
        std::shuffle(shuffled.begin(), shuffled.end(), rng);

        const size_t take = std::min(per_op, shuffled.size());
        for (size_t i = 0; i < shuffled.size(); ++i)
        {
            if (i < take)
                selected.push_back(shuffled[i]);
            else
                unselected.push_back(shuffled[i]);
        }
    }

    // Phase 2: fill remaining budget from unselected points uniformly.
    const size_t remaining = cfg.budget > selected.size()
                                 ? cfg.budget - selected.size()
                                 : 0;
    if (remaining > 0 && !unselected.empty())
    {
        // Sort unselected deterministically (by instruction_index, then op
        // pointer address) before sampling so the RNG state drives the only
        // non-determinism.
        std::sort(unselected.begin(), unselected.end(),
                  [](const MutationPoint &a, const MutationPoint &b)
                  {
                      if (a.instruction_index != b.instruction_index)
                          return a.instruction_index < b.instruction_index;
                      return a.mut < b.mut;
                  });

        std::vector<MutationPoint> fill;
        fill.reserve(remaining);
        std::sample(unselected.begin(), unselected.end(),
                    std::back_inserter(fill),
                    remaining, rng);
        for (auto &p : fill)
            selected.push_back(p);
    }

    return selected;
}

} // namespace lifted::fault_injection
