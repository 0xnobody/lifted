#include "runner.hpp"

namespace lifted::verification
{

    void DifferentialResult::print_summary(std::ostream &os) const
    {
        os << "=== Differential Test Results ===\n";
        os << "Total tests: " << total << "\n";
        os << "Passed: " << passed << "\n";
        os << "Failed: " << failed() << "\n";

        if (!failures.empty())
        {
            os << "\nFailures:\n";
            for (const auto &[idx, result] : failures)
            {
                os << "Test #" << idx << ":\n";
                result.print_summary(os);
                os << "\n";
            }
        }
    }

    llvm::Expected<DifferentialResult> run_differential_test(
        Executor &lhs,
        Executor &rhs,
        std::vector<std::unique_ptr<verifier_state>> &lhs_states,
        std::vector<std::unique_ptr<verifier_state>> &rhs_states,
        const ComparisonConfig &cmp_cfg)
    {
        if (lhs_states.size() != rhs_states.size())
        {
            return llvm::make_error<llvm::StringError>(
                "State vectors must have equal size",
                llvm::inconvertibleErrorCode());
        }

        DifferentialResult result;
        result.total = lhs_states.size();
        result.passed = 0;

        for (size_t i = 0; i < lhs_states.size(); ++i)
        {
            // Run both executors
            auto lhs_exec_result = lhs.run_single(*lhs_states[i]);
            auto rhs_exec_result = rhs.run_single(*rhs_states[i]);

            // Check both succeeded
            if (!lhs_exec_result.success || !rhs_exec_result.success)
            {
                // Treat execution failure as test failure
                // TODO: AAAAAAAA
                // ComparisonResult cmp_result;
                // cmp_result.memory = false; // Mark as diverged
                // result.failures.emplace_back(i, std::move(cmp_result));
                continue;
            }

            // Compare states
            auto cmp_result = compare_states(*lhs_states[i], *rhs_states[i], cmp_cfg);

            if (cmp_result.equivalent())
            {
                result.passed++;
            }
            else
            {
                result.failures.emplace_back(i, std::move(cmp_result));
            }
        }

        return result;
    }

    void run_single_executor(
        Executor &exec,
        std::vector<std::unique_ptr<verifier_state>> &states)
    {
        for (auto &state : states)
        {
            exec.run_single(*state);
        }
    }

} // namespace lifted::verification
