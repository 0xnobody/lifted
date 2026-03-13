#pragma once

#include "paged_memory_state.hpp"
#include "verifier_context.hpp"
#include "event_flags.hpp"
#include "value_generator.hpp"

#include <cstdint>
#include <memory>
#include <map>
#include <utility>
#include <vector>

#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include "checkpoint.hpp"

// Forward declaration — full type in binary_context.hpp.
namespace lifted { class BinaryContext; }

#define STACK_MAGIC 0x7fff00000000ULL


namespace lifted::verification
{
    enum class exit_type
    {
        NATURAL_EXIT,            // program reached a natural exit (e.g., return from entry function)
        EXCEPTION,               // program triggered an exception (e.g., divide-by-zero, invalid instruction)
        MISSING_BLOCK,           // program entered a block that was not lifted (e.g., indirect jump to an unknown target)
        CHECKPOINT_MISMATCH,     // program reached a checkpoint but the state did not match the expected state
        LAST_CHECKPOINT_REACHED, // program reached the last checkpoint (if any) without mismatches, but did not reach a natural exit
        LOOP_LIMIT,              // program exceeded the configured loop iteration limit (if any)
        BB_LIMIT,                // program exceeded the configured basic block execution limit (if any)
    };

    enum class loop_limit_policy
    {
        TERMINATE,
        FORCE_EXECUTION,
    };

    enum class recursive_call_policy
    {
        SKIP,
        FOLLOW,
    };

    struct run_params_t
    {
        uint64_t seed;
        const lifted::BinaryContext *bin_ctx = nullptr;
        uint64_t entry_rva;
        const sentinel_oracle *oracle = nullptr;
        const value_generator_factory *value_gen_factory = nullptr;
    };

    struct verification_params_t
    {
        checkpoint_config_t checkpoint_config;
        loop_limit_policy loop_policy = loop_limit_policy::TERMINATE;
        uint64_t bb_limit = UINT64_MAX;   // max basic blocks executed (UINT64_MAX = unlimited)
        uint64_t loop_limit = UINT64_MAX; // max back-edge arrivals per header (UINT64_MAX = unlimited)
        recursive_call_policy recursive_policy = recursive_call_policy::SKIP;
    };

    struct execution_flags_t
    {
        bool forced_initialization : 1 = false;
    };

    struct run_result_t
    {
        exit_type exit_reason;
        execution_flags_t flags;
        State initial_state;
        State final_state;
        memory_snapshot_t mem_snapshot;
        std::vector<uint64_t> bb_trace;
        std::vector<uint64_t> ext_calls;
        checkpoint_record_t checkpoint_record;
        std::optional<uint64_t> failed_checkpoint_idx;
    };

    /// Verifier state encapsulates execution state and trace recording.
    /// The virtual on_* methods define the execution contract - subclass to customize behavior
    /// (e.g., add checkpoints, mutate state on external calls, coverage tracking).
    class verifier_state
    {
    public:
        static constexpr uint64_t FINISH_SENTINEL = 0x0000600000000000ULL;

    protected:
        paged_memory_state mem_state;
        std::vector<uint64_t> ext_calls;

        std::vector<uint64_t> bbs_entered_rvas;
        std::unordered_map<uint64_t, uint64_t>                  bb_first_seen;       // addr -> step when first seen
        std::map<std::pair<uint64_t, uint64_t>, uint64_t>        back_edge_count;     // (from,to) -> times crossed
        uint64_t bb_step = 0;
        uint64_t bb_loop_limit = -1;
        uint64_t bb_limit = -1;
        recursive_call_policy recursive_policy_ = recursive_call_policy::SKIP;

        exit_type exit_reason = exit_type::NATURAL_EXIT;
        execution_flags_t flags{};
        std::optional<uint64_t> failed_checkpoint_idx;

        verifier_context_t verifier_context;

        checkpoint_record_t checkpoint_record;
        checkpoint_config_t checkpoint_config;
        uint64_t curr_checkpoint_idx = 0;

        event_flags log_on = event_flags::NONE;

        const sentinel_oracle *sentinel_oracle_;
        const value_generator_factory *value_gen_factory_;

        static verifier_state *from_context(void *context)
        {
            return static_cast<verifier_state *>(context);
        }

        uint64_t current_memory_contents_hash() const
        {
            return mem_state.memory_contents_digest().combined_hash();
        }

        bool assert_checkpoint(uint64_t curr_combined_hash)
        {
            if (checkpoint_config.prev_record)
            {
                if (checkpoint_config.prev_record->checkpoints.size() <= curr_checkpoint_idx + 1)
                {
                    failed_checkpoint_idx = curr_checkpoint_idx;
                    exit_reason = exit_type::LAST_CHECKPOINT_REACHED;
                    return false;
                }

                const auto &prev_cp = checkpoint_config.prev_record->checkpoints[++curr_checkpoint_idx];
                if (prev_cp.combined_hash != curr_combined_hash)
                {
                    failed_checkpoint_idx = curr_checkpoint_idx;
                    exit_reason = exit_type::CHECKPOINT_MISMATCH;
                    return false;
                }
            }

            return true;
        }

        // Virtual execution contract - override to customize behavior
        virtual bool on_read8(uint64_t addr, uint8_t &value)
        {
            value = mem_state.read8(addr);

            if (has_flag(log_on, event_flags::MEM_READ))
            {
                llvm::outs() << "on_read8 " << llvm::format_hex(addr, 16) << " -> " << llvm::format_hex(value, 2) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_READ)
                       ? assert_checkpoint(checkpoint_record.push_read(
                             addr, value, 1, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_read16(uint64_t addr, uint16_t &value)
        {
            value = mem_state.read16(addr);

            if (has_flag(log_on, event_flags::MEM_READ))
            {
                llvm::outs() << "on_read16 " << llvm::format_hex(addr, 16) << " -> " << llvm::format_hex(value, 4) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_READ)
                       ? assert_checkpoint(checkpoint_record.push_read(
                             addr, value, 2, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_read32(uint64_t addr, uint32_t &value)
        {
            value = mem_state.read32(addr);

            if (has_flag(log_on, event_flags::MEM_READ))
            {
                llvm::outs() << "on_read32 " << llvm::format_hex(addr, 16) << " -> " << llvm::format_hex(value, 8) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_READ)
                       ? assert_checkpoint(checkpoint_record.push_read(
                             addr, value, 4, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_read64(uint64_t addr, uint64_t &value)
        {
            value = mem_state.read64(addr);

            if (has_flag(log_on, event_flags::MEM_READ))
            {
                llvm::outs() << "on_read64 " << llvm::format_hex(addr, 16) << " -> " << llvm::format_hex(value, 16) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_READ)
                       ? assert_checkpoint(checkpoint_record.push_read(
                             addr, value, 8, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_write8(uint64_t addr, uint8_t value)
        {
            mem_state.write8(addr, value);

            if (has_flag(log_on, event_flags::MEM_WRITE))
            {
                llvm::outs() << "on_write8 " << llvm::format_hex(addr, 16) << " <- " << llvm::format_hex(value, 2) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_WRITE)
                       ? assert_checkpoint(checkpoint_record.push_write(
                             addr, value, 1, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_write16(uint64_t addr, uint16_t value)
        {
            mem_state.write16(addr, value);

            if (has_flag(log_on, event_flags::MEM_WRITE))
            {
                llvm::outs() << "on_write16 " << llvm::format_hex(addr, 16) << " <- " << llvm::format_hex(value, 4) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_WRITE)
                       ? assert_checkpoint(checkpoint_record.push_write(
                             addr, value, 2, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_write32(uint64_t addr, uint32_t value)
        {
            mem_state.write32(addr, value);

            if (has_flag(log_on, event_flags::MEM_WRITE))
            {
                llvm::outs() << "on_write32 " << llvm::format_hex(addr, 16) << " <- " << llvm::format_hex(value, 8) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_WRITE)
                       ? assert_checkpoint(checkpoint_record.push_write(
                             addr, value, 4, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_write64(uint64_t addr, uint64_t value)
        {
            mem_state.write64(addr, value);

            if (has_flag(log_on, event_flags::MEM_WRITE))
            {
                llvm::outs() << "on_write64 " << llvm::format_hex(addr, 16) << " <- " << llvm::format_hex(value, 16) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::MEM_WRITE)
                       ? assert_checkpoint(checkpoint_record.push_write(
                             addr, value, 8, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_bb_entered(State *state, uint64_t from_rva, uint64_t rva)
        {
            bbs_entered_rvas.push_back(rva);

            if (has_flag(log_on, event_flags::BB))
            {
                llvm::outs() << "on_bb_entered " << llvm::format_hex(from_rva, 18) << " -> "
                             << llvm::format_hex(rva, 18) << " (step: " << bb_step << ")\n";
            }

            // An edge (from, to) is a back-edge (loop iteration) when the destination
            // was already visited before this traversal — the "revisit" criterion.
            //
            // Why first_seen ordering was wrong for while-loops:
            //   A while-loop compiled with jump-to-condition layout looks like:
            //     setup → cond (initial jmp)     first_seen[cond] = T
            //     cond  → body (first entry)     first_seen[body] = T+1
            //     body  → cond (fallthrough, skipped by JIT)
            //     cond  → body (loop back-edge!) first_seen[body]=T+1 > first_seen[cond]=T
            //   The ordering test (first_seen[to] < first_seen[from]) is FALSE for
            //   cond→body even though it is the genuine loop back-edge.  Neither JIT
            //   nor Unicorn fires LOOP_LIMIT: the function runs forever.
            //
            // Revisit criterion:
            //   - First traversal of any edge: destination not yet in bb_first_seen
            //     → not counted (first entry to that block, not a loop iteration).
            //   - Second+ traversal: destination already seen → counted as back-edge.
            //
            // Handles correctly:
            //   While-loops (jump-to-condition): cond→body counted from its second
            //     traversal onward, regardless of which block was seen first.     ✓
            //   Do-while / post-tested loops: body→cond counted from 2nd traversal. ✓
            //   Self-loops (X→X): X in bb_first_seen after first entry → counted.  ✓
            //   Multi-block loops A→B→C→A: all edges accumulate together per
            //     iteration (first-pass setup traversal excluded).               ✓
            //
            // Forward edges in dispatchers or shared prefixes are also counted on
            // their second+ traversal.  Both JIT and Unicorn count them equally
            // (no divergence), and the loop limit still bounds execution.
            // The old ordering filter avoided this case but silently missed
            // while-loop back-edges, causing unbounded execution.
            //
            // UnicornExecutor normalises from_rva via FALLTHROUGH edges
            // (UnicornExecutor::normalize_from) so both executors report the same
            // canonical predecessor.  QEMU merges adjacent non-branching blocks into
            // a single translation block; the TB start is then the raw from_rva,
            // which diverges from the JIT's last_bb_rva without this normalisation.
            // This is a structural (block-boundary) dependency on lifted metadata,
            // not a semantic one — verifying IR correctness remains independent.
            if (from_rva != uint64_t(-1))
            {
                const bool is_back_edge = (bb_first_seen.count(rva) > 0);
                if (is_back_edge)
                {
                    if (++back_edge_count[{from_rva, rva}] >= bb_loop_limit)
                    {
                        exit_reason = exit_type::LOOP_LIMIT;
                        return false;
                    }
                }
            }

            if (!bb_first_seen.count(rva))
                bb_first_seen[rva] = bb_step;

            if (++bb_step > bb_limit)
            {
                exit_reason = exit_type::BB_LIMIT;
                return false;
            }

            return has_flag(checkpoint_config.sync_on, event_flags::BB)
                       ? assert_checkpoint(checkpoint_record.push_bb(
                             rva, state, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_ext_call(State *state, uint64_t addr)
        {
            ext_calls.push_back(addr);

            if (has_flag(log_on, event_flags::EXT_CALL))
            {
                llvm::outs() << "on_ext_call " << llvm::format_hex(addr, 16) << "\n";
            }

            return has_flag(checkpoint_config.sync_on, event_flags::EXT_CALL)
                       ? assert_checkpoint(checkpoint_record.push_ext_call(
                             addr, state, current_memory_contents_hash()))
                       : true;
        }

        virtual bool on_recursive_call(State *state, uint64_t addr)
        {
            // Recursive summaries participate in the same opaque-call trace as
            // external calls so comparator ext-call diffs still see skipped recursion.
            (void)state;
            ext_calls.push_back(addr);

            if (has_flag(log_on, event_flags::EXT_CALL))
            {
                llvm::outs() << "on_recursive_call " << llvm::format_hex(addr, 16) << "\n";
            }

            return true;
        }

    private:
        // Static proxies invoke virtual methods
        static bool read8_proxy(void *context, uint64_t addr, uint8_t &value)
        {
            return from_context(context)->on_read8(addr, value);
        }

        static bool read16_proxy(void *context, uint64_t addr, uint16_t &value)
        {
            return from_context(context)->on_read16(addr, value);
        }

        static bool read32_proxy(void *context, uint64_t addr, uint32_t &value)
        {
            return from_context(context)->on_read32(addr, value);
        }

        static bool read64_proxy(void *context, uint64_t addr, uint64_t &value)
        {
            return from_context(context)->on_read64(addr, value);
        }

        static bool write8_proxy(void *context, uint64_t addr, uint8_t value)
        {
            return from_context(context)->on_write8(addr, value);
        }

        static bool write16_proxy(void *context, uint64_t addr, uint16_t value)
        {
            return from_context(context)->on_write16(addr, value);
        }

        static bool write32_proxy(void *context, uint64_t addr, uint32_t value)
        {
            return from_context(context)->on_write32(addr, value);
        }

        static bool write64_proxy(void *context, uint64_t addr, uint64_t value)
        {
            return from_context(context)->on_write64(addr, value);
        }

        static bool bb_entered_proxy(void *context, State *state, uint64_t from_rva, uint64_t rva)
        {
            return from_context(context)->on_bb_entered(state, from_rva, rva);
        }

        static bool ext_call_proxy(void *context, State *state, uint64_t addr)
        {
            return from_context(context)->on_ext_call(state, addr);
        }

        static bool recursive_call_proxy(void *context, State *state, uint64_t addr)
        {
            return from_context(context)->on_recursive_call(state, addr);
        }

        void initialize_initial_state(uint64_t seed, uint64_t entry_rva)
        {
            State &initial_state = verifier_context.initial_reg_state;

            initial_state.gpr.rip.qword = LOAD_BASE + entry_rva;

            // Setup stack. We begin it at a fixed stack address.
            // We also write the 'emulation finished' sentinel return address, which allows us to see if we finished
            // execution correctly (if we don't have a specific end address).
            initial_state.gpr.rsp.qword = STACK_MAGIC;
            mem_state.write64(STACK_MAGIC, FINISH_SENTINEL);

            // Create one generator for the entire register block.
            auto reg_gen = value_gen_factory_->create(seed);

            // For each register: query the sentinel oracle first (using a deterministic
            // per-register slot seed derived from the run seed and register index);
            // fall back to the generator if no sentinel fires.
            auto gen_reg = [&](uint64_t reg_idx) -> uint64_t
            {
                if (sentinel_oracle_)
                {
                    uint64_t slot_seed = hash::mix(seed ^ 0xd00dd33dd00dd33d, reg_idx);
                    if (auto s = sentinel_oracle_->query(slot_seed, 8))
                        return s->value;
                }
                return reg_gen->generate64();
            };

            initial_state.gpr.rax.qword = gen_reg(0);
            initial_state.gpr.rbx.qword = gen_reg(1);
            initial_state.gpr.rcx.qword = gen_reg(2);
            initial_state.gpr.rdx.qword = gen_reg(3);
            initial_state.gpr.rsi.qword = gen_reg(4);
            initial_state.gpr.rdi.qword = gen_reg(5);
            initial_state.gpr.rbp.qword = gen_reg(6);
            initial_state.gpr.r8.qword = gen_reg(7);
            initial_state.gpr.r9.qword = gen_reg(8);
            initial_state.gpr.r10.qword = gen_reg(9);
            initial_state.gpr.r11.qword = gen_reg(10);
            initial_state.gpr.r12.qword = gen_reg(11);
            initial_state.gpr.r13.qword = gen_reg(12);
            initial_state.gpr.r14.qword = gen_reg(13);
            initial_state.gpr.r15.qword = gen_reg(14);
            initial_state.rflag.flat = 0x202; // default reserved bits
        }

        void initialize_context(uint64_t seed, uint64_t entry_rva)
        {
            verifier_context.read8 = &read8_proxy;
            verifier_context.read16 = &read16_proxy;
            verifier_context.read32 = &read32_proxy;
            verifier_context.read64 = &read64_proxy;

            verifier_context.write8 = &write8_proxy;
            verifier_context.write16 = &write16_proxy;
            verifier_context.write32 = &write32_proxy;
            verifier_context.write64 = &write64_proxy;

            verifier_context.bb_entered = &bb_entered_proxy;
            verifier_context.ext_call = &ext_call_proxy;
            verifier_context.recursive_call = &recursive_call_proxy;

            verifier_context.entry_rva = entry_rva;
            verifier_context.context = this;
            initialize_initial_state(seed, entry_rva);
        }

    public:
        verifier_state(const run_params_t &params, const verification_params_t &verif_params, event_flags log_on_flags = event_flags::NONE)
            : mem_state(params.seed ^ 0xFEEDFEEDFEEDFEED, params.bin_ctx, LOAD_BASE, params.oracle, params.value_gen_factory),
              ext_calls(),
              bbs_entered_rvas(),
              verifier_context(),
              log_on(log_on_flags),
              sentinel_oracle_(params.oracle),
              value_gen_factory_(params.value_gen_factory)
        {
            checkpoint_config = verif_params.checkpoint_config;
            checkpoint_record.sync_on = checkpoint_config.sync_on;
            checkpoint_record.compare_dims = checkpoint_config.compare_dims;
            if (checkpoint_config.record_details)
                checkpoint_record.enable_details();
            bb_limit = verif_params.bb_limit;
            bb_loop_limit = verif_params.loop_limit;
            recursive_policy_ = verif_params.recursive_policy;
            if (recursive_policy_ != recursive_call_policy::SKIP)
            {
                llvm::report_fatal_error("recursive_call_policy::FOLLOW is not implemented");
            }
            initialize_context(params.seed, params.entry_rva);
        }

        virtual ~verifier_state() = default;

        verifier_context_t *context_ptr()
        {
            return &verifier_context;
        }

        const verifier_context_t *context_ptr() const
        {
            return &verifier_context;
        }

        const State &get_initial_state() const
        {
            return context_ptr()->initial_reg_state;
        }

        const State &get_final_state() const
        {
            return context_ptr()->final_reg_state;
        }

        paged_memory_state &memory()
        {
            return mem_state;
        }

        const paged_memory_state &memory() const
        {
            return mem_state;
        }

        const std::vector<uint64_t> &entered_blocks() const
        {
            return bbs_entered_rvas;
        }

        const std::vector<uint64_t> &external_calls() const
        {
            return ext_calls;
        }

        void set_exit_reason(exit_type reason)
        {
            exit_reason = reason;
        }

        recursive_call_policy recursive_policy() const
        {
            return recursive_policy_;
        }

        static run_result_t finalize(verifier_state &&state)
        {
            run_result_t result =
                {
                    .exit_reason = state.exit_reason,
                    .flags = state.flags,
                    .initial_state = std::move(state.context_ptr()->initial_reg_state),
                    .final_state = std::move(state.context_ptr()->final_reg_state),
                    .mem_snapshot = paged_memory_state::finalize(std::move(state.mem_state)),
                    .bb_trace = std::move(state.bbs_entered_rvas),
                    .ext_calls = std::move(state.ext_calls),
                    .checkpoint_record = std::move(state.checkpoint_record),
                    .failed_checkpoint_idx = state.failed_checkpoint_idx};
            return result;
        }
    };

} // namespace lifted::verification
