#include "comparator.hpp"

#include <iomanip>

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Format.h>

namespace lifted::verification
{
    void ComparisonResult::print_summary(std::ostream &os) const
    {
        if (equivalent())
        {
            os << "States are EQUIVALENT\n";
            return;
        }

        os << "States DIVERGED:\n";

        if (!memory_diff.equivalent)
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

    static void render_hex_row(std::ostream &out,
                               const std::vector<uint8_t> &data,
                               const std::vector<uint8_t> &other,
                               const std::string &label)
    {
        out << "    " << label << ": ";
        for (size_t i = 0; i < data.size(); ++i)
        {
            bool differs = (i < other.size()) && data[i] != other[i];
            if (differs)
                out << "[";
            out << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
            if (differs)
                out << "]";
            if (i + 1 < data.size())
                out << " ";
        }
        out << std::dec << "\n";
    }

    static void render_write_set_delta(std::ostream &out,
                                       uint64_t page_addr,
                                       const std::bitset<4096> &written_a,
                                       const std::bitset<4096> &written_b)
    {
        // Bytes written by A only and B only — collapse into ranges for readability
        auto emit_ranges = [&](const std::bitset<4096> &mask, const char *side)
        {
            bool any = false;
            int run_start = -1;

            auto flush = [&](int run_end)
            {
                if (run_start < 0)
                    return;
                if (!any)
                {
                    out << "    Written by " << side << " only: ";
                    any = true;
                }
                else
                {
                    out << ", ";
                }
                if (run_end - run_start == 1)
                    out << "0x" << std::hex << (page_addr + run_start);
                else
                    out << "0x" << std::hex << (page_addr + run_start)
                        << "-0x" << (page_addr + run_end - 1);
                run_start = -1;
            };

            for (int i = 0; i < 4096; ++i)
            {
                if (mask.test(i))
                {
                    if (run_start < 0)
                        run_start = i;
                }
                else
                {
                    flush(i);
                }
            }
            flush(4096);

            if (any)
                out << std::dec << "\n";
        };

        std::bitset<4096> only_a = written_a & ~written_b;
        std::bitset<4096> only_b = written_b & ~written_a;
        if (only_a.any())
            emit_ranges(only_a, "A");
        if (only_b.any())
            emit_ranges(only_b, "B");
    }

    static const char *kind_str(page_diff_kind kind)
    {
        switch (kind)
        {
        case page_diff_kind::VALUE_MISMATCH:
            return "VALUE_MISMATCH";
        case page_diff_kind::WRITE_SET_MISMATCH:
            return "WRITE_SET_MISMATCH";
        case page_diff_kind::BOTH:
            return "BOTH";
        }
        return "UNKNOWN";
    }

    void ComparisonResult::print_memory_diff(std::ostream &out) const
    {
        if (memory_diff.equivalent)
        {
            out << "[OK] Memory states are equivalent.\n";
            return;
        }

        out << "[DIFF] " << memory_diff.page_diffs.size() << " page(s) differ\n\n";

        for (const auto &pd : memory_diff.page_diffs)
        {
            out << "Page 0x" << std::hex << std::setw(16) << std::setfill('0')
                << pd.page_addr << std::dec
                << "  [" << kind_str(pd.kind) << "]\n";

            // Always show write-set delta if relevant
            if (pd.kind == page_diff_kind::WRITE_SET_MISMATCH ||
                pd.kind == page_diff_kind::BOTH)
            {
                render_write_set_delta(out, pd.page_addr, pd.written_a, pd.written_b);
            }

            // Show value diffs as collapsed hex ranges
            if (!pd.ranges.empty())
            {
                for (const auto &r : pd.ranges)
                {
                    size_t len = r.end - r.start;
                    out << "  0x" << std::hex << r.start
                        << " - 0x" << (r.end - 1)
                        << " (" << std::dec << len << " byte" << (len != 1 ? "s" : "") << ")\n";
                    render_hex_row(out, r.data_a, r.data_b, "A");
                    render_hex_row(out, r.data_b, r.data_a, "B");
                }
            }
            else if (pd.kind == page_diff_kind::WRITE_SET_MISMATCH)
            {
                // Write sets differ but shared written bytes all match — nothing to hex-diff
                out << "  (no value differences in shared written bytes)\n";
            }

            out << "\n";
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
            result.memory_diff = lhs.memory().compare_detailed(rhs.memory(), cfg.excluded_memory_ranges);
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
            // Strip fallthrough-linked entries from both traces so that artificial
            // block splits introduced by the lifter don't cause false divergences.
            auto normalize = [&](const std::vector<uint64_t> &trace) -> std::vector<uint64_t>
            {
                if (cfg.fallthrough_edges.empty())
                    return trace;
                std::vector<uint64_t> out;
                out.reserve(trace.size());
                for (size_t i = 0; i < trace.size(); ++i)
                {
                    if (i > 0 && cfg.fallthrough_edges.count({trace[i - 1], trace[i]}))
                        continue;
                    out.push_back(trace[i]);
                }
                return out;
            };

            const auto lhs_trace = lhs.get_bb_record_type() == BBRecordType::ALL ? normalize(lhs.entered_blocks()) : lhs.entered_blocks();
            const auto rhs_trace = rhs.get_bb_record_type() == BBRecordType::ALL ? normalize(rhs.entered_blocks()) : rhs.entered_blocks();

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
