#pragma once

#include "verifier_state.hpp"
#include "../abi/calling_convention.hpp"

#include <iostream>
#include <string>
#include <tuple>
#include <vector>

namespace lifted::verification
{

    /// Memory range for exclusion from comparison (e.g., stack region).
    struct mem_range_t
    {
        uint64_t start;
        uint64_t end;
    };

    /// Configuration for state comparison.
    struct ComparisonConfig
    {
        bool compare_memory = true;
        bool compare_regs = true;
        bool compare_traces = true;
        bool compare_ext_calls = true;

        std::vector<mem_range_t> excluded_memory_ranges;

        const abi::CallingConvention *abi = nullptr;

        static ComparisonConfig default_config(const abi::CallingConvention *abi_ptr = nullptr)
        {
            ComparisonConfig cfg;
            cfg.abi = abi_ptr;
            return cfg;
        }
    };

    /// Result of comparing two verifier states.
    struct ComparisonResult
    {
        bool equivalent() const
        {
            return memory_equivalent && register_diffs.empty() &&
                   trace_diffs.empty() && ext_call_diffs.empty();
        }

        // Memory: bool only (detailed diffs can be huge, added later if needed)
        bool memory_equivalent = true;

        // Registers: detailed (State is small)
        std::vector<std::tuple<std::string, uint64_t, uint64_t>> register_diffs; // (name, lhs, rhs)

        // Traces: detailed
        std::vector<std::tuple<size_t, uint64_t, uint64_t>> trace_diffs; // (index, lhs_bb, rhs_bb)

        // External calls: detailed
        std::vector<std::tuple<size_t, uint64_t, uint64_t>> ext_call_diffs; // (index, lhs_addr, rhs_addr)

        void print(std::ostream &os) const;
    };

    /// Compare two verifier states for equivalence.
    ComparisonResult compare_states(
        const verifier_state &lhs,
        const verifier_state &rhs,
        const ComparisonConfig &cfg);

} // namespace lifted::verification
