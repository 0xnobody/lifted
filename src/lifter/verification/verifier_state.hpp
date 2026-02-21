#pragma once

#include "paged_memory_state.hpp"
#include "verifier_context.hpp"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include <random>

#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#define STACK_MAGIC 0x7fff00000000ULL

namespace lifted::verification
{
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
        std::unordered_map<uint64_t, uint64_t> bb_first_seen;   // addr -> step when first seen
        std::unordered_map<uint64_t, uint32_t> bb_header_count; // addr -> back-edge arrivals
        uint64_t bb_step = 0;
        uint64_t bb_prev = -1;
        uint64_t bb_loop_limit = -1;
        uint64_t bb_limit = -1;

        verifier_context_t verifier_context;

        // Authoritative sentinel oracle. verifier_state owns it by value; a copy is pushed
        // into mem_state via attach_oracle() so mem_state has no lifetime dependency on us.
        std::optional<sentinel_oracle> sentinel_oracle_;

        static verifier_state *from_context(void *context)
        {
            return static_cast<verifier_state *>(context);
        }

        // Virtual execution contract - override to customize behavior
        virtual bool on_read8(uint64_t addr, uint8_t &value)
        {
            value = mem_state.read8(addr);
            return true;
        }

        virtual bool on_read16(uint64_t addr, uint16_t &value)
        {
            value = mem_state.read16(addr);
            return true;
        }

        virtual bool on_read32(uint64_t addr, uint32_t &value)
        {
            value = mem_state.read32(addr);
            return true;
        }

        virtual bool on_read64(uint64_t addr, uint64_t &value)
        {
            value = mem_state.read64(addr);
            return true;
        }

        virtual bool on_write8(uint64_t addr, uint8_t value)
        {
            mem_state.write8(addr, value);
            return true;
        }

        virtual bool on_write16(uint64_t addr, uint16_t value)
        {
            mem_state.write16(addr, value);
            return true;
        }

        virtual bool on_write32(uint64_t addr, uint32_t value)
        {
            mem_state.write32(addr, value);
            return true;
        }

        virtual bool on_write64(uint64_t addr, uint64_t value)
        {
            mem_state.write64(addr, value);
            return true;
        }

        virtual bool on_bb_entered(State *state, uint64_t rva)
        {
            bbs_entered_rvas.push_back(rva);

            if (!bb_first_seen.count(rva))
            {
                bb_first_seen[rva] = bb_step;
            }

            if (bb_prev != -1 && bb_first_seen[rva] < bb_first_seen[bb_prev])
                // back edge: addr was seen before prev → addr is a loop header
                if (++bb_header_count[rva] >= bb_loop_limit)
                {
                    // TODO: do something, reached limit
                }

            bb_prev = rva;
            return true;
        }

        virtual bool on_ext_call(State *state, uint64_t addr)
        {
            ext_calls.push_back(addr);
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

        static bool bb_entered_proxy(void *context, State *state, uint64_t rva)
        {
            return from_context(context)->on_bb_entered(state, rva);
        }

        static bool ext_call_proxy(void *context, State *state, uint64_t addr)
        {
            return from_context(context)->on_ext_call(state, addr);
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

            std::mt19937_64 rng(seed);
            std::uniform_int_distribution<uint64_t> reg_dis(0, UINT64_MAX);

            initial_state.gpr.rax.qword = reg_dis(rng);
            initial_state.gpr.rbx.qword = reg_dis(rng);
            initial_state.gpr.rcx.qword = reg_dis(rng);
            initial_state.gpr.rdx.qword = reg_dis(rng);
            initial_state.gpr.rsi.qword = reg_dis(rng);
            initial_state.gpr.rdi.qword = reg_dis(rng);
            initial_state.gpr.rbp.qword = reg_dis(rng);
            initial_state.gpr.r8.qword = reg_dis(rng);
            initial_state.gpr.r9.qword = reg_dis(rng);
            initial_state.gpr.r10.qword = reg_dis(rng);
            initial_state.gpr.r11.qword = reg_dis(rng);
            initial_state.gpr.r12.qword = reg_dis(rng);
            initial_state.gpr.r13.qword = reg_dis(rng);
            initial_state.gpr.r14.qword = reg_dis(rng);
            initial_state.gpr.r15.qword = reg_dis(rng);
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

            verifier_context.entry_rva = entry_rva;
            verifier_context.context = this;
            initialize_initial_state(seed, entry_rva);
        }

    public:
        verifier_state(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t entry_rva = 0)
            : mem_state(seed ^ 0xFEEDFEEDFEEDFEED, std::move(binary), LOAD_BASE),
              bbs_entered_rvas(),
              ext_calls(),
              verifier_context()
        {
            initialize_context(seed, entry_rva);
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

        // Set (or replace) the sentinel oracle used for memory reads.
        // Both verifier_state and paged_memory_state own independent copies,
        // so moves/copies of either do not create dangling pointers.
        void set_oracle(sentinel_oracle o)
        {
            sentinel_oracle_ = std::move(o);
            mem_state.attach_oracle(sentinel_oracle_);
        }

        void clear_oracle()
        {
            sentinel_oracle_.reset();
            mem_state.attach_oracle(std::nullopt);
        }

        const std::optional<sentinel_oracle> &get_oracle() const
        {
            return sentinel_oracle_;
        }
    };

} // namespace lifted::verification
