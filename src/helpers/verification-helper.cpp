/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"

#include "../lifted/verification/jit_executor_context.hpp" // ew

jit_executor_context_t *__ctx;

HELPER Memory *__lifted_ext_call(State *__restrict__, addr_t addr, Memory *);
HELPER Memory *__lifted_recursive_call(State *__restrict__, addr_t addr, Memory *);

void assert_exit(bool value)
{
    if (!value)
    {
        longjmp(__ctx->exit_jmp, 1);
    }
}

void synchronize_flags(State *__restrict__ s)
{
    // The lifted IR writes individual arithmetic flags into state.aflag.* but
    // never updates state.rflag.flat (that packed field is only written by
    // PUSHF/POPF semantics).  Pack aflag -> rflag here so the comparator sees
    // the correct flag values.
    s->rflag.cf = s->aflag.cf;
    s->rflag.pf = s->aflag.pf;
    s->rflag.af = s->aflag.af;
    s->rflag.zf = s->aflag.zf;
    s->rflag.sf = s->aflag.sf;
    s->rflag.df = s->aflag.df;
    s->rflag.of = s->aflag.of;
}

HELPER uint8_t __lifted_read_memory_8(addr_t a)
{
    uint8_t value;
    assert_exit(__ctx->verifier_context->read8(__ctx->verifier_context->context, a, value));
    return value;
}

HELPER uint16_t __lifted_read_memory_16(addr_t a)
{
    uint16_t value;
    assert_exit(__ctx->verifier_context->read16(__ctx->verifier_context->context, a, value));
    return value;
}

HELPER uint32_t __lifted_read_memory_32(addr_t a)
{
    uint32_t value;
    assert_exit(__ctx->verifier_context->read32(__ctx->verifier_context->context, a, value));
    return value;
}

HELPER uint64_t __lifted_read_memory_64(addr_t a)
{
    uint64_t value;
    assert_exit(__ctx->verifier_context->read64(__ctx->verifier_context->context, a, value));
    return value;
}

HELPER void __lifted_write_memory_8(addr_t a, uint8_t v)
{
    assert_exit(__ctx->verifier_context->write8(__ctx->verifier_context->context, a, v));
}

HELPER void __lifted_write_memory_16(addr_t a, uint16_t v)
{
    assert_exit(__ctx->verifier_context->write16(__ctx->verifier_context->context, a, v));
}

HELPER void __lifted_write_memory_32(addr_t a, uint32_t v)
{
    assert_exit(__ctx->verifier_context->write32(__ctx->verifier_context->context, a, v));
}

HELPER void __lifted_write_memory_64(addr_t a, uint64_t v)
{
    assert_exit(__ctx->verifier_context->write64(__ctx->verifier_context->context, a, v));
}

HELPER void __lifted_memset_memory(addr_t addr, uint8_t byte, uint64_t len)
{
    for (uint64_t i = 0; i < len; ++i)
    {
        __lifted_write_memory_8(addr + i, byte);
    }
}

HELPER void __lifted_memcpy_memory(addr_t dst, addr_t src, uint64_t len)
{
    for (uint64_t i = 0; i < len; ++i)
    {
        uint8_t byte = __lifted_read_memory_8(src + i);
        __lifted_write_memory_8(dst + i, byte);
    }
}

HELPER void __lifted_memmove_memory(addr_t dst, addr_t src, uint64_t len)
{
    if (dst <= src || dst - src >= len)
    {
        for (uint64_t i = 0; i < len; ++i)
        {
            uint8_t byte = __lifted_read_memory_8(src + i);
            __lifted_write_memory_8(dst + i, byte);
        }
        return;
    }

    for (uint64_t i = len; i != 0; --i)
    {
        uint8_t byte = __lifted_read_memory_8(src + i - 1);
        __lifted_write_memory_8(dst + i - 1, byte);
    }
}

HELPER __attribute__((pure)) Memory *__lifted_bb_entered(State state, addr_t a, Memory *m) // Pass state byval so it's not an optimization barrier.
{
    synchronize_flags(&state);

    assert_exit(__ctx->verifier_context->bb_entered(__ctx->verifier_context->context, &state, __ctx->last_bb_rva, a));
    __ctx->last_bb_rva = a;
    return m;
}

HELPER Memory *__lifted_ext_call(State *state, addr_t addr, Memory *m)
{
    synchronize_flags(state);

    assert_exit(__ctx->verifier_context->ext_call(__ctx->verifier_context->context, state, addr));
    return m;
}

HELPER Memory *__lifted_verifier_ext_call(State *state, addr_t addr, Memory *m, uint64_t annotation_id)
{
    (void)annotation_id;
    synchronize_flags(state);

    assert_exit(__ctx->verifier_context->ext_call(__ctx->verifier_context->context, state, addr));
    return m;
}

HELPER Memory *__lifted_recursive_call(State *state, addr_t addr, Memory *m)
{
    synchronize_flags(state);

    assert_exit(__ctx->verifier_context->recursive_call(
        __ctx->verifier_context->context, state, addr));
    return m;
}

// extern "C" Memory *__lifted_rebuilt_cfg(State &state, addr_t rva, Memory *memory, uint64_t base);
extern "C" Memory *__lifted_rebuilt_cfg_concrete(State &state, Memory *memory, uint64_t base);

extern "C" void __lifter_verifier_begin(jit_executor_context_t *executor_ctx)
{
    State state = executor_ctx->verifier_context->initial_reg_state;
    __ctx = executor_ctx;

    int jump_val = setjmp(executor_ctx->exit_jmp);
    if (jump_val == 0)
    {
        // __lifted_rebuilt_cfg(state, executor_ctx->verifier_context->entry_rva, nullptr, LOAD_BASE);
        __lifted_rebuilt_cfg_concrete(state, nullptr, LOAD_BASE);
    }

    synchronize_flags(&state);

    executor_ctx->verifier_context->final_reg_state = state;
}