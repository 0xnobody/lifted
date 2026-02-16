#pragma once

#include "comparator.hpp"
#include "executor.hpp"
#include "verifier_state.hpp"

#include <llvm/Support/Error.h>

#include <iostream>
#include <memory>
#include <vector>

namespace lifted::verification
{

    /// Result of differential testing between two executors.
    struct DifferentialResult
    {
        size_t total;
        size_t passed;

        size_t failed() const { return total - passed; }

        std::vector<std::pair<size_t, ComparisonResult>> failures; // (test_index, divergences)

        void print_summary(std::ostream &os) const;
    };

    /// Run differential test between two executors.
    /// States must be pre-generated (allows custom verifier_state subclasses).
    /// Both state vectors must have the same size and use matching seeds.
    llvm::Expected<DifferentialResult> run_differential_test(
        Executor &lhs,
        Executor &rhs,
        std::vector<std::unique_ptr<verifier_state>> &lhs_states,
        std::vector<std::unique_ptr<verifier_state>> &rhs_states,
        const ComparisonConfig &cmp_cfg);

    /// Run a single executor on test states (non-comparative).
    void run_single_executor(
        Executor &exec,
        std::vector<std::unique_ptr<verifier_state>> &states);

} // namespace lifted::verification
