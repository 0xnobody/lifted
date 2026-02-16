#include "runner.hpp"
#include "test_generator.hpp"
#include "unicorn_executor.hpp"
#include "jit_executor.hpp"
#include "comparator.hpp"
#include "../abi/systemv_x64.hpp"
#include "../utils.hpp"

#include <LIEF/LIEF.hpp>
#include <llvm/Support/Error.h>

#include <iostream>

namespace lifted::verification
{

    /// Example: Compare lifted IR against obfuscated binary via Unicorn emulation
    llvm::Error example_ir_vs_binary(
        const std::string &binary_path,
        const std::string &lifted_ir_path,
        const std::string &function_name,
        uint64_t entry_rva,
        size_t num_tests = 100,
        uint64_t seed_base = 0x1337)
    {
        std::cout << "=== Differential Testing: Lifted IR vs Binary ===\n\n";

        // Load binary
        std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(binary_path);
        if (!binary)
        {
            return llvm::make_error<llvm::StringError>(
                "Failed to parse binary: " + binary_path,
                llvm::inconvertibleErrorCode());
        }

        // Load lifted IR module
        llvm::LLVMContext ctx;
        auto module = utils::load_module_from_file(lifted_ir_path, ctx);
        if (!module)
        {
            return module.takeError();
        }

        // Create executors
        auto unicorn_exec = UnicornExecutor::create(binary_path, {}, entry_rva);
        if (!unicorn_exec)
        {
            return unicorn_exec.takeError();
        }

        auto jit_exec = JITExecutor::create(std::move(*module), function_name);
        if (!jit_exec)
        {
            return jit_exec.takeError();
        }

        // Generate test states (separate vectors for each executor)
        auto unicorn_states = generate_test_states(binary, entry_rva, num_tests, seed_base);
        auto jit_states = generate_test_states(binary, entry_rva, num_tests, seed_base);

        // Configure comparison
        abi::SystemVx64CC abi;
        ComparisonConfig cmp_cfg;
        cmp_cfg.abi = &abi;
        cmp_cfg.compare_all_regs = false; // Only ABI-relevant registers
        cmp_cfg.excluded_memory_ranges = {{STACK_MAGIC - (1024 * 1024), STACK_MAGIC}};

        // Run differential test
        auto result = run_differential_test(
            **unicorn_exec, **jit_exec,
            unicorn_states, jit_states, cmp_cfg);

        if (!result)
        {
            return result.takeError();
        }

        // Print results
        result->print_summary(std::cout);

        return llvm::Error::success();
    }

    /// Example: Compare two IR variants (e.g., lifted vs deobfuscated)
    llvm::Error example_ir_vs_ir(
        const std::string &binary_path,
        const std::string &lifted_ir_path,
        const std::string &deob_ir_path,
        const std::string &function_name,
        uint64_t entry_rva,
        size_t num_tests = 100)
    {
        std::cout << "=== Differential Testing: Lifted IR vs Deobfuscated IR ===\n\n";

        std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(binary_path);
        if (!binary)
        {
            return llvm::make_error<llvm::StringError>(
                "Failed to parse binary",
                llvm::inconvertibleErrorCode());
        }

        llvm::LLVMContext ctx1, ctx2;
        auto lifted_module = utils::load_module_from_file(lifted_ir_path, ctx1);
        if (!lifted_module)
        {
            return lifted_module.takeError();
        }

        auto deob_module = utils::load_module_from_file(deob_ir_path, ctx2);
        if (!deob_module)
        {
            return deob_module.takeError();
        }

        auto lifted_exec = JITExecutor::create(std::move(*lifted_module), function_name);
        if (!lifted_exec)
        {
            return lifted_exec.takeError();
        }

        auto deob_exec = JITExecutor::create(std::move(*deob_module), function_name);
        if (!deob_exec)
        {
            return deob_exec.takeError();
        }

        auto lifted_states = generate_test_states(binary, entry_rva, num_tests, 0x1337);
        auto deob_states = generate_test_states(binary, entry_rva, num_tests, 0x1337);

        abi::SystemVx64CC abi;
        ComparisonConfig cmp_cfg = ComparisonConfig::default_config(&abi);

        auto result = run_differential_test(
            **lifted_exec, **deob_exec,
            lifted_states, deob_states, cmp_cfg);

        if (!result)
        {
            return result.takeError();
        }

        result->print_summary(std::cout);
        return llvm::Error::success();
    }

    /// Example: Compare with all registers (for debugging)
    llvm::Error example_all_registers_comparison(
        const std::string &binary_path,
        const std::string &ir_path,
        const std::string &function_name,
        uint64_t entry_rva)
    {
        std::cout << "=== Full Register Comparison ===\n\n";

        std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(binary_path);
        if (!binary)
        {
            return llvm::make_error<llvm::StringError>("Failed to parse binary", llvm::inconvertibleErrorCode());
        }

        llvm::LLVMContext ctx;
        auto module = utils::load_module_from_file(ir_path, ctx);
        if (!module)
        {
            return module.takeError();
        }

        auto unicorn_exec = UnicornExecutor::create(binary_path, {}, entry_rva);
        if (!unicorn_exec)
        {
            return unicorn_exec.takeError();
        }

        auto jit_exec = JITExecutor::create(std::move(*module), function_name);
        if (!jit_exec)
        {
            return jit_exec.takeError();
        }

        auto unicorn_states = generate_test_states(binary, entry_rva, 10, 0x1337);
        auto jit_states = generate_test_states(binary, entry_rva, 10, 0x1337);

        // Use AllRegistersCC for full comparison
        abi::AllRegistersCC all_regs_abi;
        ComparisonConfig cmp_cfg;
        cmp_cfg.abi = &all_regs_abi;
        cmp_cfg.compare_all_regs = true;

        auto result = run_differential_test(
            **unicorn_exec, **jit_exec,
            unicorn_states, jit_states, cmp_cfg);

        if (!result)
        {
            return result.takeError();
        }

        result->print_summary(std::cout);
        return llvm::Error::success();
    }

    /// Example: Custom verifier_state with checkpointing
    class CheckpointVerifierState : public verifier_state
    {
    private:
        size_t bb_limit;
        size_t bb_count = 0;

    protected:
        void on_bb_entered(State *state, uint64_t rva) override
        {
            // Call base implementation
            verifier_state::on_bb_entered(state, rva);

            // Custom checkpoint logic
            bb_count++;
            if (bb_limit > 0 && bb_count >= bb_limit)
            {
                std::cout << "Checkpoint: Reached " << bb_count << " basic blocks, stopping early\n";
                // In a real implementation, you might throw an exception or set a flag
                // to stop execution early
            }
        }

    public:
        CheckpointVerifierState(uint64_t seed, std::shared_ptr<LIEF::Binary> binary,
                                uint64_t entry_rva, size_t limit = 0)
            : verifier_state(seed, binary, entry_rva), bb_limit(limit)
        {
        }
    };

    llvm::Error example_custom_verifier_state(
        const std::string &binary_path,
        uint64_t entry_rva,
        size_t bb_limit = 100)
    {
        std::cout << "=== Custom Verifier State with Checkpointing ===\n\n";

        std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(binary_path);
        if (!binary)
        {
            return llvm::make_error<llvm::StringError>("Failed to parse binary", llvm::inconvertibleErrorCode());
        }

        auto unicorn_exec = UnicornExecutor::create(binary_path, {}, entry_rva);
        if (!unicorn_exec)
        {
            return unicorn_exec.takeError();
        }

        // Generate custom test states
        auto states = generate_custom_test_states<CheckpointVerifierState>(
            binary, entry_rva, 5, 0x1337);

        // Run tests
        run_single_executor(**unicorn_exec, states);

        std::cout << "Completed " << states.size() << " tests with custom checkpointing\n";
        return llvm::Error::success();
    }

} // namespace lifted::verification
