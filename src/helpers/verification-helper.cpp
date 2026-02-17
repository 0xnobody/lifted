/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"

#include "standard-intrinsics.hpp"

#include "../shared/verifier_context.hpp" // ew

struct Memory
{
    verifier_context_t *__lifted_verifier_context;
};

HELPER Memory *__lifted_ext_call(State *__restrict__, addr_t addr, Memory *);

HELPER uint8_t __remill_read_memory_8(Memory *m, addr_t a)
{
    return m->__lifted_verifier_context->read8(m->__lifted_verifier_context->context, a);
}

HELPER uint16_t __remill_read_memory_16(Memory *m, addr_t a)
{
    return m->__lifted_verifier_context->read16(m->__lifted_verifier_context->context, a);
}

HELPER uint32_t __remill_read_memory_32(Memory *m, addr_t a)
{
    return m->__lifted_verifier_context->read32(m->__lifted_verifier_context->context, a);
}

HELPER uint64_t __remill_read_memory_64(Memory *m, addr_t a)
{
    return m->__lifted_verifier_context->read64(m->__lifted_verifier_context->context, a);
}

HELPER Memory *__remill_write_memory_8(Memory *m, addr_t a, uint8_t v)
{
    m->__lifted_verifier_context->write8(m->__lifted_verifier_context->context, a, v);
    return m;
}

HELPER Memory *__remill_write_memory_16(Memory *m, addr_t a, uint16_t v)
{
    m->__lifted_verifier_context->write16(m->__lifted_verifier_context->context, a, v);
    return m;
}

HELPER Memory *__remill_write_memory_32(Memory *m, addr_t a, uint32_t v)
{
    m->__lifted_verifier_context->write32(m->__lifted_verifier_context->context, a, v);
    return m;
}

HELPER Memory *__remill_write_memory_64(Memory *m, addr_t a, uint64_t v)
{
    m->__lifted_verifier_context->write64(m->__lifted_verifier_context->context, a, v);
    return m;
}

HELPER Memory *__lifted_bb_entered(State *state, addr_t a, Memory *m)
{
    m->__lifted_verifier_context->bb_entered(m->__lifted_verifier_context->context, state, a);
    return m;
}

HELPER Memory *__lifted_ext_call(State *state, addr_t addr, Memory *m)
{
    m->__lifted_verifier_context->ext_call(m->__lifted_verifier_context->context, state, addr);
    return m;
}

extern "C" Memory *__lifted_rebuilt_cfg(State &state, addr_t rva, Memory *memory, uint64_t base);

extern "C" void __lifter_verifier_begin(verifier_context_t *verifier_state)
{
    //__lifted_verifier_context = verifier_state;

    State state = verifier_state->initial_reg_state;
    Memory m = {.__lifted_verifier_context = verifier_state};
    __lifted_rebuilt_cfg(state, verifier_state->entry_rva, &m, LOAD_BASE);
    verifier_state->final_reg_state = state;
}