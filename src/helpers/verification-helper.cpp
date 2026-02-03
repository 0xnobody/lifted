/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"

#include "standard-intrinsics.hpp"
#include "verification.hpp"

HELPER uint8_t __remill_read_memory_8(Memory *m, addr_t a)
{
    return m->m.read8(a);
}

HELPER uint16_t __remill_read_memory_16(Memory *m, addr_t a)
{
    return m->m.read16(a);
}

HELPER uint32_t __remill_read_memory_32(Memory *m, addr_t a)
{
    return m->m.read32(a);
}

HELPER uint64_t __remill_read_memory_64(Memory *m, addr_t a)
{
    return m->m.read64(a);
}

HELPER Memory *__remill_write_memory_8(Memory *m, addr_t a, uint8_t v)
{
    m->m.write8(a, v);
    return m;
}

HELPER Memory *__remill_write_memory_16(Memory *m, addr_t a, uint16_t v)
{
    m->m.write16(a, v);
    return m;
}

HELPER Memory *__remill_write_memory_32(Memory *m, addr_t a, uint32_t v)
{
    m->m.write32(a, v);
    return m;
}

HELPER Memory *__remill_write_memory_64(Memory *m, addr_t a, uint64_t v)
{
    m->m.write64(a, v);
    return m;
}

HELPER Memory *__lifted_bb_entered(State &state, Memory *m)
{
}

HELPER Memory *__lifted_bb_exited(State &state, Memory *m)
{
}

extern "C" Memory *__remill_function(State &state, addr_t address, Memory *memory);

extern "C" Memory *__unfold_function_systemv_x64_abi(addr_t address,
                                                     Memory *__restrict__ memory,
                                                     rptr8 rcx,
                                                     rptr8 rdx,
                                                     rptr8 rsp,
                                                     rptr8 rsi,
                                                     rptr8 rdi,
                                                     rptr8 rax)
{
    // Local state structure for improved optimisations
    State state = {};

    // Reset the rflags
    state.rflag.flat = 0;

    // Init local GPRs
    state.gpr.rcx.qword = *rcx;
    state.gpr.rdx.qword = *rdx;
    state.gpr.rsp.qword = *rsp;
    state.gpr.rsi.qword = *rsi;
    state.gpr.rdi.qword = *rdi;
    state.gpr.rip.qword = address;

    // Execute the lifted function
    memory = __remill_function(state, address, memory);

    // Load updated GPRs
    *rax = state.gpr.rax.qword;

    // Return the memory pointer
    return memory;
}
