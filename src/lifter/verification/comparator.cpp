#include "comparator.hpp"

#include <iomanip>

namespace lifted::verification
{

    void ComparisonResult::print(std::ostream &os) const
    {
        if (equivalent())
        {
            os << "States are EQUIVALENT\n";
            return;
        }

        os << "States DIVERGED:\n";

        if (!memory_equivalent)
        {
            os << "  - Memory differs\n";
        }

        if (!register_diffs.empty())
        {
            os << "  - Register differences:\n";
            for (const auto &[name, lhs, rhs] : register_diffs)
            {
                os << "    " << name << ": 0x" << std::hex << lhs
                   << " vs 0x" << rhs << std::dec << "\n";
            }
        }

        if (!trace_diffs.empty())
        {
            os << "  - Trace differences (" << trace_diffs.size() << " divergences):\n";
            for (const auto &[idx, lhs_bb, rhs_bb] : trace_diffs)
            {
                os << "    [" << idx << "]: 0x" << std::hex << lhs_bb
                   << " vs 0x" << rhs_bb << std::dec << "\n";
            }
        }

        if (!ext_call_diffs.empty())
        {
            os << "  - External call differences (" << ext_call_diffs.size() << " divergences):\n";
            for (const auto &[idx, lhs_addr, rhs_addr] : ext_call_diffs)
            {
                os << "    [" << idx << "]: 0x" << std::hex << lhs_addr
                   << " vs 0x" << rhs_addr << std::dec << "\n";
            }
        }
    }

    ComparisonResult compare_states(
        const verifier_state &lhs,
        const verifier_state &rhs,
        const ComparisonConfig &cfg)
    {
        ComparisonResult result;

        // Memory comparison
        if (cfg.compare_memory)
        {
            // Use paged_memory_state comparison (respects excluded ranges)
            result.memory_equivalent = lhs.memory().compare(rhs.memory());
        }

        // Register comparison
        if (cfg.abi && cfg.compare_regs)
        {
            const State &lhs_state = lhs.get_final_state();
            const State &rhs_state = rhs.get_final_state();

            // Get divergent registers from ABI
            auto divergences = cfg.abi->get_divergent_registers(lhs_state, rhs_state);
            result.register_diffs = std::move(divergences);
        }

        // Trace comparison
        if (cfg.compare_traces)
        {
            const auto &lhs_trace = lhs.entered_blocks();
            const auto &rhs_trace = rhs.entered_blocks();

            size_t min_len = std::min(lhs_trace.size(), rhs_trace.size());
            for (size_t i = 0; i < min_len; ++i)
            {
                if (lhs_trace[i] != rhs_trace[i])
                {
                    result.trace_diffs.emplace_back(i, lhs_trace[i], rhs_trace[i]);
                }
            }

            // Handle length mismatches
            if (lhs_trace.size() != rhs_trace.size())
            {
                size_t max_len = std::max(lhs_trace.size(), rhs_trace.size());
                for (size_t i = min_len; i < max_len; ++i)
                {
                    uint64_t lhs_bb = i < lhs_trace.size() ? lhs_trace[i] : 0;
                    uint64_t rhs_bb = i < rhs_trace.size() ? rhs_trace[i] : 0;
                    result.trace_diffs.emplace_back(i, lhs_bb, rhs_bb);
                }
            }
        }

        // External call comparison
        if (cfg.compare_ext_calls)
        {
            const auto &lhs_calls = lhs.external_calls();
            const auto &rhs_calls = rhs.external_calls();

            size_t min_len = std::min(lhs_calls.size(), rhs_calls.size());
            for (size_t i = 0; i < min_len; ++i)
            {
                if (lhs_calls[i] != rhs_calls[i])
                {
                    result.ext_call_diffs.emplace_back(i, lhs_calls[i], rhs_calls[i]);
                }
            }

            // Handle length mismatches
            if (lhs_calls.size() != rhs_calls.size())
            {
                size_t max_len = std::max(lhs_calls.size(), rhs_calls.size());
                for (size_t i = min_len; i < max_len; ++i)
                {
                    uint64_t lhs_addr = i < lhs_calls.size() ? lhs_calls[i] : 0;
                    uint64_t rhs_addr = i < rhs_calls.size() ? rhs_calls[i] : 0;
                    result.ext_call_diffs.emplace_back(i, lhs_addr, rhs_addr);
                }
            }
        }

        return result;
    }

} // namespace lifted::verification
