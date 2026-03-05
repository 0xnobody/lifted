/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"

#include "standard-intrinsics.hpp"

#include "../lifted/verification/jit_executor_context.hpp" // ew

struct Memory
{
    jit_executor_context_t *ctx;
};

HELPER Memory *__lifted_ext_call(State *__restrict__, addr_t addr, Memory *);

void assert_exit(Memory *m, bool value)
{
    if (!value)
    {
        longjmp(m->ctx->exit_jmp, 1);
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

HELPER uint8_t __remill_read_memory_8(Memory *m, addr_t a)
{
    uint8_t value;
    assert_exit(m, m->ctx->verifier_context->read8(m->ctx->verifier_context->context, a, value));
    return value;
}

HELPER uint16_t __remill_read_memory_16(Memory *m, addr_t a)
{
    uint16_t value;
    assert_exit(m, m->ctx->verifier_context->read16(m->ctx->verifier_context->context, a, value));
    return value;
}

HELPER uint32_t __remill_read_memory_32(Memory *m, addr_t a)
{
    uint32_t value;
    assert_exit(m, m->ctx->verifier_context->read32(m->ctx->verifier_context->context, a, value));
    return value;
}

HELPER uint64_t __remill_read_memory_64(Memory *m, addr_t a)
{
    uint64_t value;
    assert_exit(m, m->ctx->verifier_context->read64(m->ctx->verifier_context->context, a, value));
    return value;
}

HELPER Memory *__remill_write_memory_8(Memory *m, addr_t a, uint8_t v)
{
    assert_exit(m, m->ctx->verifier_context->write8(m->ctx->verifier_context->context, a, v));
    return m;
}

HELPER Memory *__remill_write_memory_16(Memory *m, addr_t a, uint16_t v)
{
    assert_exit(m, m->ctx->verifier_context->write16(m->ctx->verifier_context->context, a, v));
    return m;
}

HELPER Memory *__remill_write_memory_32(Memory *m, addr_t a, uint32_t v)
{
    assert_exit(m, m->ctx->verifier_context->write32(m->ctx->verifier_context->context, a, v));
    return m;
}

HELPER Memory *__remill_write_memory_64(Memory *m, addr_t a, uint64_t v)
{
    assert_exit(m, m->ctx->verifier_context->write64(m->ctx->verifier_context->context, a, v));
    return m;
}

HELPER __attribute__((pure)) Memory *__lifted_bb_entered(State state, addr_t a, Memory *m) // Pass state byval so it's not an optimization barrier.
{
    synchronize_flags(&state);

    if (!m->ctx->is_fallthrough_edge(m->ctx->last_bb_rva, a, m->ctx->executor_data))
    {
        assert_exit(m, m->ctx->verifier_context->bb_entered(m->ctx->verifier_context->context, &state, a));
    }
    m->ctx->last_bb_rva = a;
    return m;
}

HELPER Memory *__lifted_ext_call(State *state, addr_t addr, Memory *m)
{
    synchronize_flags(state);

    assert_exit(m, m->ctx->verifier_context->ext_call(m->ctx->verifier_context->context, state, addr));
    return m;
}

extern "C" Memory *__lifted_rebuilt_cfg(State &state, addr_t rva, Memory *memory, uint64_t base);

extern "C" void __lifter_verifier_begin(jit_executor_context_t *executor_ctx)
{
    State state = executor_ctx->verifier_context->initial_reg_state;
    Memory m = {.ctx = executor_ctx};

    int jump_val = setjmp(executor_ctx->exit_jmp);
    if (jump_val == 0)
    {
        __lifted_rebuilt_cfg(state, executor_ctx->verifier_context->entry_rva, &m, LOAD_BASE);
    }

    synchronize_flags(&state);

    executor_ctx->verifier_context->final_reg_state = state;
}