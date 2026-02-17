#pragma once

#include "paged_memory_state.hpp"
#include "verifier_context.hpp"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>
#include <random>

class verifier_state
{
private:
    State initial_state;
    State final_state;
    paged_memory_state mem_state;
    std::vector<uint64_t> bbs_entered;
    std::vector<uint64_t> ext_calls;

    verifier_context_t verifier_context;

    static verifier_state *from_context(void *context)
    {
        return static_cast<verifier_state *>(context);
    }

    static uint8_t read8_proxy(void *context, uint64_t addr)
    {
        return from_context(context)->mem_state.read8(addr);
    }

    static uint16_t read16_proxy(void *context, uint64_t addr)
    {
        return from_context(context)->mem_state.read16(addr);
    }

    static uint32_t read32_proxy(void *context, uint64_t addr)
    {
        return from_context(context)->mem_state.read32(addr);
    }

    static uint64_t read64_proxy(void *context, uint64_t addr)
    {
        return from_context(context)->mem_state.read64(addr);
    }

    static void write8_proxy(void *context, uint64_t addr, uint8_t value)
    {
        from_context(context)->mem_state.write8(addr, value);
    }

    static void write16_proxy(void *context, uint64_t addr, uint16_t value)
    {
        from_context(context)->mem_state.write16(addr, value);
    }

    static void write32_proxy(void *context, uint64_t addr, uint32_t value)
    {
        from_context(context)->mem_state.write32(addr, value);
    }

    static void write64_proxy(void *context, uint64_t addr, uint64_t value)
    {
        from_context(context)->mem_state.write64(addr, value);
    }

    static void bb_entered_proxy(void *context, State *state, uint64_t rva)
    {
        (void)state;
        from_context(context)->bbs_entered.push_back(rva);
    }

    static void ext_call_proxy(void *context, State *state, uint64_t addr)
    {
        (void)state;
        from_context(context)->ext_calls.push_back(addr);
    }

    void initialize_context(uint64_t entry_rva)
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
        verifier_context.initial_reg_state = initial_state;
        verifier_context.final_reg_state = final_state;
    }

    void initialize_initial_state(uint64_t seed, uint64_t entry_rva)
    {
        initial_state.gpr.rip.qword = LOAD_BASE + entry_rva;
        initial_state.gpr.rsp.qword = STACK_MAGIC;

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

public:
    verifier_state(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t entry_rva = 0)
        : initial_state(),
          final_state(),
          mem_state(seed ^ 0xFEEDFEEDFEEDFEED, std::move(binary), LOAD_BASE),
          bbs_entered(),
          ext_calls(),
          verifier_context()
    {
        initialize_context(entry_rva);
        initialize_initial_state(seed, entry_rva);
    }

    verifier_context_t *context_ptr()
    {
        return &verifier_context;
    }

    const verifier_context_t *context_ptr() const
    {
        return &verifier_context;
    }

    void clear_trace()
    {
        bbs_entered.clear();
        ext_calls.clear();
    }

    void sync_final_state_from_context()
    {
        final_state = verifier_context.final_reg_state;
    }

    const State &get_initial_state() const
    {
        return initial_state;
    }

    const State &get_final_state() const
    {
        return final_state;
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
        return bbs_entered;
    }

    const std::vector<uint64_t> &external_calls() const
    {
        return ext_calls;
    }
};