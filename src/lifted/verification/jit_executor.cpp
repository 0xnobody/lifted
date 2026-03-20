#include <csignal>
#include <setjmp.h>
#include <set>
#include <vector>

#include "jit_executor.hpp"
#include "../abi/function_state_attrs.hpp"
#include "../helpers.hpp"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/TargetSelect.h>

#include "../passes/verification/memory_intrinsic_lowering_pass.hpp"

#include "../utils.hpp"
#include "../opt.hpp"

#include "jit_executor_context.hpp"

// --- JIT fault recovery ---------------------------------------------------
// Hardware faults (SIGFPE, SIGSEGV, SIGILL, SIGBUS) raised by JIT-compiled
// code cannot be caught with try/catch — they are OS signals.  We use
// sigsetjmp/siglongjmp to unwind cleanly and report exit_type::EXCEPTION.
//
// thread_local: sigaction handlers are process-global, but synchronous
// hardware faults are always delivered to the faulting thread, so per-thread
// state is sufficient and safe for concurrent JIT runs.
static thread_local sigjmp_buf tl_fault_buf;
static thread_local bool       tl_in_jit = false;

static void jit_fault_handler(int sig)
{
    if (tl_in_jit)
    {
        tl_in_jit = false;
        siglongjmp(tl_fault_buf, sig);
    }
    // Fault occurred outside a JIT execution — restore the default handler
    // and re-raise so that genuine crashes still terminate the process.
    signal(sig, SIG_DFL);
    raise(sig);
}
// ---------------------------------------------------------------------------

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

        // Lower verification memory intrinsics
        opt::run_fnc_pass_on_module<MemoryIntrinsicLoweringPass>(*module.get());

        // Sanity check that RAM global either doesn't exist, or has 0 uses.
        auto *ram_global = module->getGlobalVariable("RAM");
        if (ram_global && !ram_global->hasNUses(0))
        {
            return llvm::make_error<llvm::StringError>(
                "RAM global still has uses after memory intrinsic lowering. All memory intrinsics must be lowered to RAM[...] before JIT execution.",
                llvm::inconvertibleErrorCode());
        }

        auto *verifierExtFunc = module->getFunction("__lifted_verifier_ext_call");
        if (!verifierExtFunc)
        {
            return llvm::make_error<llvm::StringError>(
                "Missing __lifted_verifier_ext_call function declaration",
                llvm::inconvertibleErrorCode());
        }

        std::vector<llvm::Function *> named_ext_calls;
        for (auto &F : module->functions())
            if (F.getName().starts_with("__lifted_ext_call_"))
                named_ext_calls.push_back(&F);

        for (auto *named_ext : named_ext_calls)
        {
            auto annotation_id_or = abi::get_annotation_id(*named_ext);
            if (!annotation_id_or)
                return annotation_id_or.takeError();

            std::vector<llvm::CallBase *> callsites;
            for (auto *U : named_ext->users())
                if (auto *CB = llvm::dyn_cast<llvm::CallBase>(U))
                    callsites.push_back(CB);

            for (auto *CB : callsites)
            {
                if (CB->arg_size() != 3)
                {
                    return llvm::make_error<llvm::StringError>(
                        "named external call stub has unexpected arity",
                        llvm::inconvertibleErrorCode());
                }

                llvm::IRBuilder<> B(CB);
                auto *new_call = B.CreateCall(
                    verifierExtFunc,
                    {CB->getArgOperand(0),
                     CB->getArgOperand(1),
                     CB->getArgOperand(2),
                     B.getInt64(annotation_id_or->value)});
                new_call->setCallingConv(CB->getCallingConv());
                if (CB->hasName())
                    new_call->setName(CB->getName());
                CB->replaceAllUsesWith(new_call);
                CB->eraseFromParent();
            }

            if (named_ext->use_empty() && named_ext->isDeclaration())
                named_ext->eraseFromParent();
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
        auto tsm = llvm::orc::ThreadSafeModule(std::move(module), std::make_unique<llvm::LLVMContext>());

        // Note: We need to transfer ownership properly
        if (auto err = jit->addIRModule(std::move(tsm)))
        {
            return err;
        }

        // Lookup entry function (triggers JIT compilation)
        auto sym = jit->lookup("__lifter_verifier_begin");
        if (!sym)
        {
            return sym.takeError();
        }

        // Cast to function pointer
        entry_fn = reinterpret_cast<fn_verifier_begin>(sym->getValue());

        return llvm::Error::success();
    }

    llvm::Error JITExecutor::run_single_impl(verifier_state &state)
    {
        jit_executor_context_t executor_ctx = {
            .verifier_context = state.context_ptr(),
        };

        // Install fault-recovery handlers, saving whatever was there before
        // (LLVM or the OS default).  SA_RESETHAND is intentionally absent so
        // the handler persists for the full duration of this call.
        struct sigaction sa{}, old_fpe, old_segv, old_ill, old_bus;
        sa.sa_handler = jit_fault_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGFPE,  &sa, &old_fpe);
        sigaction(SIGSEGV, &sa, &old_segv);
        sigaction(SIGILL,  &sa, &old_ill);
        sigaction(SIGBUS,  &sa, &old_bus);

        // sigsetjmp with savesigs=1: saves the signal mask so that after a
        // siglongjmp recovery SIGFPE (etc.) is not left blocked in the thread
        // mask — which would cause the next fault to kill the process.
        int fault_sig = 0;
        tl_in_jit = true;
        if ((fault_sig = sigsetjmp(tl_fault_buf, 1)) == 0)
        {
            entry_fn(&executor_ctx);
            tl_in_jit = false;
        }
        // tl_in_jit is already false here — cleared on the normal path above
        // or by the signal handler before it called siglongjmp.

        sigaction(SIGFPE,  &old_fpe,  nullptr);
        sigaction(SIGSEGV, &old_segv, nullptr);
        sigaction(SIGILL,  &old_ill,  nullptr);
        sigaction(SIGBUS,  &old_bus,  nullptr);

        if (fault_sig != 0)
            state.set_exit_reason(exit_type::EXCEPTION);

        return llvm::Error::success();
    }

} // namespace lifted::verification
