#include "jit_executor.hpp"
#include "../helpers.hpp"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/Support/TargetSelect.h>

#include "../utils.hpp"

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

        auto *extCallFunc = module->getFunction("__lifted_ext_call");
        if (!extCallFunc)
        {
            return llvm::make_error<llvm::StringError>(
                "Missing __lifted_ext_call function declaration",
                llvm::inconvertibleErrorCode());
        }

        // TODO: better interop between lifter and this
        for (auto &F : module->functions())
        {
            if (F.getName().starts_with("__lifted_ext_call_"))
            {
                F.replaceAllUsesWith(extCallFunc);
            }
        }

        utils::output_to_file("/home/atlas/lifted/out/jit_input.ll", module.get());

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

        // Expose symbols from the current process (e.g. libc memcpy/memset)
        // to ORC so unresolved runtime symbols can be resolved.
        llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
        auto process_symbols_or_err = llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
            jit->getDataLayout().getGlobalPrefix());
        if (!process_symbols_or_err)
        {
            return process_symbols_or_err.takeError();
        }

        jit->getMainJITDylib().addGenerator(std::move(*process_symbols_or_err));

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

        // TODO: Track instruction count
        return ExecutionResult::ok(0);
    }

} // namespace lifted::verification
