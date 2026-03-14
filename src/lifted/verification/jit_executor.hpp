#pragma once

#include "executor.hpp"

#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <memory>
#include <string>

struct jit_executor_context_t;

namespace lifted::verification
{
    /// Executor that runs lifted LLVM IR via ORC JIT.
    class JITExecutor : public Executor
    {
    private:
        using fn_verifier_begin = void (*)(jit_executor_context_t *);

        std::unique_ptr<llvm::Module> module;
        std::unique_ptr<llvm::orc::LLJIT> jit;
        fn_verifier_begin entry_fn;
        std::string function_name;

        JITExecutor(std::unique_ptr<llvm::Module> mod, std::string fn)
            : module(std::move(mod)),
              jit(nullptr),
              entry_fn(nullptr),
              function_name(std::move(fn))
        {
        }

    protected:
        llvm::Error setup_impl() override;
        llvm::Error run_single_impl(verifier_state &state) override;

    public:
        std::string_view name() const override { return "JIT"; }
        static llvm::Expected<std::unique_ptr<JITExecutor>>
        create(std::unique_ptr<llvm::Module> module, const std::string &fn_name);
    };

} // namespace lifted::verification
