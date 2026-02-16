#pragma once

#include <llvm/Support/Error.h>

#include <string>

namespace lifted::verification
{

    /// Example: Compare lifted IR against obfuscated binary via Unicorn emulation.
    /// This is the primary use case - validating that lifted IR behaves identically
    /// to the original binary.
    llvm::Error example_ir_vs_binary(
        const std::string &binary_path,
        const std::string &lifted_ir_path,
        const std::string &function_name,
        uint64_t entry_rva,
        size_t num_tests = 100,
        uint64_t seed_base = 0x1337);

    /// Example: Compare two IR variants (e.g., lifted vs deobfuscated).
    /// Useful for validating that deobfuscation passes preserve semantics.
    llvm::Error example_ir_vs_ir(
        const std::string &binary_path,
        const std::string &lifted_ir_path,
        const std::string &deob_ir_path,
        const std::string &function_name,
        uint64_t entry_rva,
        size_t num_tests = 100);

    /// Example: Compare with all registers (for debugging).
    /// Uses AllRegistersCC to compare all 16 GPRs instead of just ABI-relevant ones.
    llvm::Error example_all_registers_comparison(
        const std::string &binary_path,
        const std::string &ir_path,
        const std::string &function_name,
        uint64_t entry_rva);

    /// Example: Custom verifier_state with checkpointing.
    /// Demonstrates how to extend verifier_state to add custom behavior
    /// (e.g., early stopping, coverage tracking, state mutation).
    llvm::Error example_custom_verifier_state(
        const std::string &binary_path,
        uint64_t entry_rva,
        size_t bb_limit = 100);

} // namespace lifted::verification
