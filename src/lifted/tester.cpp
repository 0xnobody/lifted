/*
#include "tester.hpp"

#include "helpers.hpp"

#include "../shared/verifier_state.hpp"

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/ExecutionEngine/Orc/ThreadSafeModule.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/Support/DynamicLibrary.h"

#include "utils.hpp"

#include <fstream>

namespace lifted
{
    llvm::Expected<verifier_state> run_verifier_test(
        llvm::Function *remill_function,
        uint64_t seed,
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_addr)
    {
        if (!remill_function)
        {
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: remill_function is null",
                llvm::inconvertibleErrorCode());
        }

        llvm::Module *source_module = remill_function->getParent();
        if (!source_module)
        {
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: remill_function has no parent module",
                llvm::inconvertibleErrorCode());
        }

        if (remill_function->getName() != "__remill_function")
        {
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: expected function named __remill_function",
                llvm::inconvertibleErrorCode());
        }

        auto verifier_module = llvm::CloneModule(*source_module);

        utils::output_to_file("/home/atlas/lifted/out/test_jit.ll", verifier_module.get());

        if (!verifier_module->getFunction("__lifter_verifier_begin"))
        {
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: __lifter_verifier_begin not found after linking verification intrinsics",
                llvm::inconvertibleErrorCode());
        }

        // Initialize native target for JIT
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();

        // Create LLJIT instance
        auto jit_or_err = llvm::orc::LLJITBuilder().create();
        if (!jit_or_err)
        {
            std::string error_msg;
            llvm::handleAllErrors(
                jit_or_err.takeError(),
                [&](const llvm::ErrorInfoBase &EI)
                {
                    error_msg = EI.message();
                });
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: failed to create LLJIT: " + error_msg,
                llvm::inconvertibleErrorCode());
        }
        auto jit = std::move(*jit_or_err);

        // Expose symbols from the current process (e.g. libc memcpy/memset)
        // to ORC so unresolved runtime symbols can be resolved.
        llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
        auto process_symbols_or_err = llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
            jit->getDataLayout().getGlobalPrefix());
        if (!process_symbols_or_err)
        {
            std::string error_msg;
            llvm::handleAllErrors(
                process_symbols_or_err.takeError(),
                [&](const llvm::ErrorInfoBase &EI)
                {
                    error_msg = EI.message();
                });
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: failed to create process symbol generator: " + error_msg,
                llvm::inconvertibleErrorCode());
        }

        jit->getMainJITDylib().addGenerator(std::move(*process_symbols_or_err));

        // Wrap module in ThreadSafeContext and add to JIT
        auto ctx = std::make_unique<llvm::LLVMContext>();
        auto tsm = llvm::orc::ThreadSafeModule(std::move(verifier_module), std::move(ctx));

        if (auto err = jit->addIRModule(std::move(tsm)))
        {
            std::string error_msg;
            llvm::handleAllErrors(
                std::move(err),
                [&](const llvm::ErrorInfoBase &EI)
                {
                    error_msg = EI.message();
                });
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: failed to add IR module: " + error_msg,
                llvm::inconvertibleErrorCode());
        }

        // Look up the function symbol
        auto begin_sym = jit->lookup("__lifter_verifier_begin");
        if (!begin_sym)
        {
            std::string error_msg;
            llvm::handleAllErrors(
                begin_sym.takeError(),
                [&](const llvm::ErrorInfoBase &EI)
                {
                    error_msg = EI.message();
                });
            return llvm::make_error<llvm::StringError>(
                "run_verifier_test: failed to resolve __lifter_verifier_begin: " + error_msg,
                llvm::inconvertibleErrorCode());
        }

        // Convert ExecutorAddr to function pointer
        const uint64_t begin_addr = begin_sym->getValue();

        verifier_state state(seed, std::move(binary), entry_addr);

        using begin_fn_t = void (*)(verifier_context_t *);
        auto begin_fn = reinterpret_cast<begin_fn_t>(begin_addr);
        begin_fn(state.context_ptr());

        state.sync_final_state_from_context();
        return state;
    }
}
*/