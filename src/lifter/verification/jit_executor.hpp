#pragma once

#include "executor.hpp"

#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <memory>
#include <string>

namespace lifted::verification
{

    /// Executor that runs lifted LLVM IR via ORC JIT.
    class JITExecutor : public Executor
    {
    private:
        using fn_verifier_begin = void (*)(verifier_context_t *);

        std::unique_ptr<llvm::Module> module;
        std::unique_ptr<llvm::orc::LLJIT> jit;
        void (*entry_fn)(verifier_context_t *);
        std::string function_name;
        std::set<std::pair<uint64_t, uint64_t>> fallthrough_edges;

        JITExecutor(std::unique_ptr<llvm::Module> mod, std::string fn, const std::set<std::pair<uint64_t, uint64_t>> &fallthrough_edges)
            : module(std::move(mod)),
              jit(nullptr),
              entry_fn(nullptr),
              function_name(std::move(fn)),
              fallthrough_edges(fallthrough_edges)
        {
        }

        static bool is_fallthrough_edge(uint64_t from, uint64_t to, void *executor_data);

    protected:
        llvm::Error setup_impl() override;
        ExecutionResult run_single_impl(verifier_state &state) override;

    public:
        static llvm::Expected<std::unique_ptr<JITExecutor>>
        create(std::unique_ptr<llvm::Module> module, const std::string &fn_name, const std::set<std::pair<uint64_t, uint64_t>> &fallthrough_edges = {});
    };

} // namespace lifted::verification
