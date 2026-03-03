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

#include "../hash_mix.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace lifted::verification
{
    /// Hash for std::pair<uint64_t, uint64_t> using Murmur3 mixing.
    struct U64PairHash
    {
        size_t operator()(std::pair<uint64_t, uint64_t> const &p) const noexcept
        {
            return hash::mix(p.first, p.second);
        }
    };

    /// Hash for std::pair<uint64_t, uint32_t> — used as (tb_start, tb_size) cache key.
    struct U64U32PairHash
    {
        size_t operator()(std::pair<uint64_t, uint32_t> const &p) const noexcept
        {
            return hash::mix(p.first, static_cast<uint64_t>(p.second));
        }
    };

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
        std::unordered_set<uint64_t> external_rvas; // RVAs of external functions (e.g. imports) to skip
        std::unique_ptr<uc_engine, decltype(&uc_close)> uc_eng;
        std::unique_ptr<uc_context, decltype(&uc_context_free)> clean_ctx;
        uint64_t entry_rva;
        Flags flags;

        std::unordered_set<uint64_t> rep_artifacts; // TB starts identified as REP/split artifacts
        std::unordered_set<std::pair<uint64_t, uint64_t>, U64PairHash> genuine_edges;

        /// Cache: (tb_start_va, tb_size) → does the last instruction end in a branch?
        /// Persists across run_single_impl calls — binary code is static.
        std::unordered_map<std::pair<uint64_t, uint32_t>, bool, U64U32PairHash> tb_branch_cache;

        UnicornExecutor(std::shared_ptr<LIEF::Binary> bin, std::unordered_set<uint64_t> ext_rvas, uint64_t entry, Flags flags)
            : binary(std::move(bin)),
              external_rvas(std::move(ext_rvas)),
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
        create(std::shared_ptr<LIEF::Binary> bin, std::unordered_set<uint64_t> ext_rvas, uint64_t entry_rva, Flags flags = Flags::NONE);

        void hint_external_rvas(const std::unordered_set<uint64_t> &rvas) override;

    private:
        /// Forward-scan the translation block [pc, pc+size) to determine whether its last
        /// instruction is a branch/call/ret/interrupt. Results are cached by (pc, size).
        ///
        /// Forward scanning from the TB start — a guaranteed valid x86 instruction boundary
        /// provided by Unicorn/TCG — is the only reliable way to find the last instruction
        /// in a variable-length ISA. Backward scanning from the TB end can misidentify
        /// mid-instruction bytes as a valid shorter instruction.
        bool tb_ends_in_branch(uc_engine *uc, uint64_t pc, uint32_t size);

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
