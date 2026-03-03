#pragma once

#include "verifier_state.hpp"

#include <llvm/Support/Error.h>

#include <memory>
#include <vector>
#include <unordered_set>

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
        virtual llvm::Error run_single_impl(verifier_state &state) = 0;

    public:
        virtual ~Executor() = default;

        /// Inform the executor of newly discovered external call targets from prior src runs.
        /// Called by the pipeline before each run_single. Default no-op.
        /// UnicornExecutor overrides to insert into its live external_rvas set.
        virtual void hint_external_rvas(const std::unordered_set<uint64_t> &) {}

        /// Run a single test case.
        llvm::Expected<run_result_t> run_single(const run_params_t &run_params, const verification_params_t &verif_params, event_flags log_on_flags = event_flags::NONE)
        {
            verifier_state state(run_params, verif_params, log_on_flags);
            auto err = run_single_impl(state);
            if (err)
            {
                return err;
            }
            return verifier_state::finalize(std::move(state));
        }
    };

} // namespace lifted::verification
