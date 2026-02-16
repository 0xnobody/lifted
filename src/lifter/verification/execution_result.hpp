#pragma once

#include <cstdint>
#include <string>

namespace lifted::verification
{

    /// Reason emulation/JIT execution stopped.
    enum class StopReason
    {
        NORMAL,           // Reached finish address successfully
        TIMEOUT,          // Max instructions exceeded
        CRASH,            // Exception/fault occurred
        UNSUPPORTED_INSN, // Encountered unsupported instruction
        MEMORY_FAULT      // Unmappable memory access
    };

    /// Result of a single test execution.
    struct ExecutionResult
    {
        bool success;
        StopReason reason;
        uint64_t instruction_count;
        std::string error_msg; // Empty if success

        static ExecutionResult ok(uint64_t insn_count = 0)
        {
            return {true, StopReason::NORMAL, insn_count, ""};
        }

        static ExecutionResult error(StopReason r, std::string msg, uint64_t insn_count = 0)
        {
            return {false, r, insn_count, std::move(msg)};
        }
    };

} // namespace lifted::verification
