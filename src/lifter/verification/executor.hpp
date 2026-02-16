#pragma once

#include "execution_result.hpp"
#include "verifier_state.hpp"

#include <llvm/Support/Error.h>

#include <memory>
#include <vector>

namespace lifted::verification
{

    /// Abstract executor base class.
    /// Executors run lifted code (JIT) or native binaries (Unicorn emulation).
    /// Use static create() factory to construct - ensures setup succeeds before use.
    class Executor
    {
    protected:
        Executor() = default; // Protected constructor - use factory

        /// Subclasses implement setup logic (linking helpers, creating JIT/emulator, etc.)
        /// Return llvm::Error::success() on success, error otherwise.
        virtual llvm::Error setup_impl() = 0;

        /// Execute a single test case. State contains initial conditions, execution
        /// populates final state and traces.
        virtual ExecutionResult run_single_impl(verifier_state &state) = 0;

    public:
        virtual ~Executor() = default;

        /// Run a single test case.
        ExecutionResult run_single(verifier_state &state)
        {
            return run_single_impl(state);
        }

        /// Run multiple tests (convenience wrapper).
        /// States are created externally - allows custom verifier_state subclasses.
        void run_tests(std::vector<std::unique_ptr<verifier_state>> &states)
        {
            for (auto &state : states)
            {
                run_single(*state);
            }
        }
    };

} // namespace lifted::verification
