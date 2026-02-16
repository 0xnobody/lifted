#include "jit_executor.hpp"
#include "../helpers.hpp"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/Support/TargetSelect.h>

namespace lifted::verification
{

    llvm::Expected<std::unique_ptr<JITExecutor>>
    JITExecutor::create(std::unique_ptr<llvm::Module> module, const std::string &fn_name)
    {
        // Create executor (private constructor)
        auto executor = std::unique_ptr<JITExecutor>(
            new JITExecutor(std::move(module), fn_name));

        // Run setup
        if (auto err = executor->setup_impl())
        {
            return std::move(err);
        }

        return executor;
    }

    llvm::Error JITExecutor::setup_impl()
    {
        // Link verification intrinsics
        if (auto err = helpers::link_verification_intrinsics(module.get()))
        {
            return err;
        }

        // Initialize native target for JIT
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();

        // Create LLJIT
        auto jit_builder = llvm::orc::LLJITBuilder();
        auto jit_expected = jit_builder.create();
        if (!jit_expected)
        {
            return jit_expected.takeError();
        }
        jit = std::move(*jit_expected);

        // Add module to JIT
        auto &ctx = module->getContext();
        auto tsm = llvm::orc::ThreadSafeModule(std::move(module), std::make_unique<llvm::LLVMContext>());

        // Note: We need to transfer ownership properly
        if (auto err = jit->addIRModule(std::move(tsm)))
        {
            return err;
        }

        // Lookup entry function
        auto sym = jit->lookup("__lifter_verifier_begin");
        if (!sym)
        {
            return sym.takeError();
        }

        // Cast to function pointer
        entry_fn = reinterpret_cast<void (*)(verifier_context_t *)>(sym->getValue());

        return llvm::Error::success();
    }

    ExecutionResult JITExecutor::run_single_impl(verifier_state &state)
    {
        // Call JIT function with verifier context
        entry_fn(state.context_ptr());

        // Sync final state from context
        state.sync_final_state_from_context();

        // TODO: Track instruction count
        return ExecutionResult::ok(0);
    }

} // namespace lifted::verification
