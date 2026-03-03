#pragma once

#include "executor.hpp"
#include "state_conversion.hpp"
#include "uc_raii.hpp"

#include <llvm/Support/Error.h>

#ifdef DEBUG
#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG
#else
#include <LIEF/LIEF.hpp>
#endif

#include <memory>
#include <string>
#include <set>

namespace lifted::verification
{
    /// Executor that runs native binaries via Unicorn emulation.
    class UnicornExecutor : public Executor
    {
    public:
        enum class Flags : uint32_t
        {
            NONE = 0,
            LOG_INSTRUCTIONS = 1 << 0, // Log each instruction executed (for debugging)
        };

    private:
        std::shared_ptr<LIEF::Binary> binary;
        std::set<uint64_t> external_rvas; // RVAs of external functions (e.g. imports) to skip
        std::unique_ptr<uc_engine, decltype(&uc_close)> uc_eng;
        std::unique_ptr<uc_context, decltype(&uc_context_free)> clean_ctx;
        uint64_t entry_rva;
        Flags flags;

        std::set<uint64_t> rep_artifacts; // TB starts identified as REP/split artifacts
        std::set<std::pair<uint64_t, uint64_t>> genuine_edges;

        UnicornExecutor(std::shared_ptr<LIEF::Binary> bin, std::set<uint64_t> ext_rvas, uint64_t entry, Flags flags)
            : binary(std::move(bin)),
              external_rvas(ext_rvas),
              uc_eng(nullptr, uc_close),
              clean_ctx(nullptr, uc_context_free),
              entry_rva(entry),
              flags(flags)
        {
        }

    protected:
        llvm::Error setup_impl() override;
        llvm::Error run_single_impl(verifier_state &state) override;

    public:
        static llvm::Expected<std::unique_ptr<UnicornExecutor>>
        create(std::shared_ptr<LIEF::Binary> bin, std::set<uint64_t> ext_rvas, uint64_t entry_rva, Flags flags = Flags::NONE);

    private:
        static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
        static void hook_edge(uc_engine *uc, uc_tb *cur_tb, uc_tb *prev_tb, void *user_data);
        static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address,
                                     int size, int64_t value, void *user_data);
        static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                                  int size, int64_t value, void *user_data);
        static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                                   int size, int64_t value, void *user_data);
    };

    inline UnicornExecutor::Flags operator|(UnicornExecutor::Flags a, UnicornExecutor::Flags b) { return static_cast<UnicornExecutor::Flags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b)); }
    inline UnicornExecutor::Flags operator&(UnicornExecutor::Flags a, UnicornExecutor::Flags b) { return static_cast<UnicornExecutor::Flags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b)); }
    inline bool has_flag(UnicornExecutor::Flags flags, UnicornExecutor::Flags flag) { return (flags & flag) != UnicornExecutor::Flags::NONE; }

} // namespace lifted::verification
