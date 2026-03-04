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
        llvm::Error run_single_impl(verifier_state &state) override;

    public:
        std::string_view name() const override { return "JIT"; }
        static llvm::Expected<std::unique_ptr<JITExecutor>>
        create(std::unique_ptr<llvm::Module> module, const std::string &fn_name, const std::set<std::pair<uint64_t, uint64_t>> &fallthrough_edges = {});
    };

} // namespace lifted::verification
