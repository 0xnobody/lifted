#include "jit_executor.hpp"
#include "../helpers.hpp"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/Support/TargetSelect.h>

#include "../passes/verification/memory_intrinsic_lowering_pass.hpp"

#include "../utils.hpp"
#include "../opt.hpp"

#include "jit_executor_context.hpp"

namespace lifted::verification
{

    llvm::Expected<std::unique_ptr<JITExecutor>>
    JITExecutor::create(std::unique_ptr<llvm::Module> module, const std::string &fn_name, const std::set<std::pair<uint64_t, uint64_t>> &fallthrough_edges)
    {
        // Create executor (private constructor)
        auto executor = std::unique_ptr<JITExecutor>(
            new JITExecutor(std::move(module), fn_name, fallthrough_edges));

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

        utils::output_to_file("/home/atlas/lifted/out/jit_input.ll", module.get());

        // Lower verification memory intrinsics
        opt::run_fnc_pass_on_module<MemoryIntrinsicLoweringPass>(*module.get());

        utils::output_to_file("/home/atlas/lifted/out/jit_input.ll", module.get());

        // Sanity check that RAM global either doesn't exist, or has 0 uses.
        auto *ram_global = module->getGlobalVariable("RAM");
        if (ram_global && !ram_global->hasNUses(0))
        {
            return llvm::make_error<llvm::StringError>(
                "RAM global still has uses after memory intrinsic lowering. All memory intrinsics must be lowered to RAM[...] before JIT execution.",
                llvm::inconvertibleErrorCode());
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
        entry_fn = reinterpret_cast<fn_verifier_begin>(sym->getValue());

        return llvm::Error::success();
    }

    bool JITExecutor::is_fallthrough_edge(uint64_t from, uint64_t to, void *executor_data)
    {
        auto *executor = static_cast<JITExecutor *>(executor_data);
        return executor->fallthrough_edges.contains({from, to});
    }

    llvm::Error JITExecutor::run_single_impl(verifier_state &state)
    {
        jit_executor_context_t executor_ctx = {
            .verifier_context = state.context_ptr(),
            .is_fallthrough_edge = is_fallthrough_edge,
            .executor_data = this};

        // Call JIT function with verifier context
        entry_fn(&executor_ctx);

        return llvm::Error::success();
    }

} // namespace lifted::verification
