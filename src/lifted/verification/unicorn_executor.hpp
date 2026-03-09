#pragma once

#include "executor.hpp"
#include "state_conversion.hpp"
#include "uc_raii.hpp"

#include <llvm/Support/Error.h>

#include "compat/lief_compat.hpp"

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

        /// Describes the external-call topology for a lifted function.
        /// Supplied once at construction so no per-run hints are needed.
        ///
        /// ext_function_rvas:        RVAs of callee entry-points reached via CALL to a
        ///                           known external target (PLT stubs, helper functions, etc.).
        ///                           Populated from SYNTHETIC_EXTERNAL synthetic_block entries.
        ///
        /// indr_dispatch_block_rvas: RVAs of the *dispatcher* basic blocks that perform
        ///                           indirect calls (e.g. `call [rax]`). Destinations are
        ///                           unknown ahead-of-time; hook_block detects them by
        ///                           checking whether the previous real BB was one of these
        ///                           dispatchers and treats the landed block as an ext call.
        struct ext_call_info_t
        {
            std::unordered_set<uint64_t> ext_function_rvas;
            std::unordered_set<uint64_t> indr_dispatch_block_rvas;
        };

    private:
        const lifted::BinaryContext *bin_ctx_; ///< Non-owning; must outlive this executor.
        std::unordered_set<uint64_t> ext_rvas_;          // RVAs of known external callees
        std::unordered_set<uint64_t> indr_dispatch_rvas_; // RVAs of indirect-call dispatcher BBs
        std::unique_ptr<uc_engine, decltype(&uc_close)> uc_eng;
        std::unique_ptr<uc_context, decltype(&uc_context_free)> clean_ctx;
        uint64_t entry_rva;
        Flags flags;

        std::unordered_set<uint64_t> rep_artifacts; // TB starts identified as REP/split artifacts
        std::unordered_set<std::pair<uint64_t, uint64_t>, U64PairHash> genuine_edges;

        /// Result of a translation-block branch analysis.
        /// Cached by (tb_start_va, tb_size) — binary code is static so results never change.
        struct tb_branch_result_t
        {
            bool is_branch   = false;
            bool is_indirect = false; // meaningful only when is_branch == true
        };

        /// Cache: (tb_start_va, tb_size) → branch analysis result.
        /// Persists across run_single_impl calls — binary code is static.
        std::unordered_map<std::pair<uint64_t, uint32_t>, tb_branch_result_t, U64U32PairHash> tb_branch_cache;

        /// Set when any indirect branch (jmp reg/mem, call reg/mem) is observed in hook_edge.
        /// When true, the TB cache is flushed before each run to prevent stale inline-cache
        /// targets from directing execution to the wrong block.
        bool has_indirect_branches_ = false;

        /// Lifter FALLTHROUGH edges as {from_start_rva → to_start_rva}.
        /// Used to normalise QEMU's TB-start prev_block to the actual logical
        /// predecessor before counting directed back-edges.
        std::unordered_map<uint64_t, uint64_t> fallthrough_edges_;

        UnicornExecutor(const lifted::BinaryContext *bin_ctx, ext_call_info_t ext_info, uint64_t entry, Flags flags,
                        std::unordered_map<uint64_t, uint64_t> fallthrough_edges)
            : bin_ctx_(bin_ctx),
              ext_rvas_(std::move(ext_info.ext_function_rvas)),
              indr_dispatch_rvas_(std::move(ext_info.indr_dispatch_block_rvas)),
              uc_eng(nullptr, uc_close),
              clean_ctx(nullptr, uc_context_free),
              entry_rva(entry),
              flags(flags),
              fallthrough_edges_(std::move(fallthrough_edges))
        {
        }

    protected:
        llvm::Error setup_impl() override;
        llvm::Error run_single_impl(verifier_state &state) override;

    public:
        std::string_view name() const override { return "Unicorn"; }
        static llvm::Expected<std::unique_ptr<UnicornExecutor>>
        create(const lifted::BinaryContext &bin_ctx, ext_call_info_t ext_info, uint64_t entry_rva,
               Flags flags = Flags::NONE,
               std::unordered_map<uint64_t, uint64_t> fallthrough_edges = {});
    private:
        /// Forward-scan the translation block [pc, pc+size) to determine whether its last
        /// instruction is a branch/call/ret/interrupt, and whether it is an indirect branch.
        /// Results are cached by (pc, size).
        ///
        /// Forward scanning from the TB start — a guaranteed valid x86 instruction boundary
        /// provided by Unicorn/TCG — is the only reliable way to find the last instruction
        /// in a variable-length ISA. Backward scanning from the TB end can misidentify
        /// mid-instruction bytes as a valid shorter instruction.
        tb_branch_result_t tb_ends_in_branch(uc_engine *uc, uint64_t pc, uint32_t size);

        /// Normalise a TB-start from_rva to the last block in the FALLTHROUGH
        /// chain that lies within [from_rva, from_rva + from_tb_size).
        /// Returns from_rva unchanged if no FALLTHROUGH edges apply.
        uint64_t normalize_from(uint64_t from_rva, uint32_t from_tb_size) const noexcept;

        static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
        static void hook_edge(uc_engine *uc, uc_tb *cur_tb, uc_tb *prev_tb, void *user_data);
        static bool hook_tlb_fill(uc_engine *uc, uint64_t address,
                                   uc_mem_type type, uc_tlb_entry *result, void *user_data);
        static void hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                                  int size, int64_t value, void *user_data);
        static void hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                                   int size, int64_t value, void *user_data);
    };

    inline UnicornExecutor::Flags operator|(UnicornExecutor::Flags a, UnicornExecutor::Flags b) { return static_cast<UnicornExecutor::Flags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b)); }
    inline UnicornExecutor::Flags operator&(UnicornExecutor::Flags a, UnicornExecutor::Flags b) { return static_cast<UnicornExecutor::Flags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b)); }
    inline bool has_flag(UnicornExecutor::Flags flags, UnicornExecutor::Flags flag) { return (flags & flag) != UnicornExecutor::Flags::NONE; }

} // namespace lifted::verification
