#pragma once

#include <cstdint>

#include <remill/Arch/X86/Runtime/State.h>

using fn_read8 = uint8_t (*)(void *context, uint64_t addr);
using fn_read16 = uint16_t (*)(void *context, uint64_t addr);
using fn_read32 = uint32_t (*)(void *context, uint64_t addr);
using fn_read64 = uint64_t (*)(void *context, uint64_t addr);

using fn_write8 = void (*)(void *context, uint64_t addr, uint8_t value);
using fn_write16 = void (*)(void *context, uint64_t addr, uint16_t value);
using fn_write32 = void (*)(void *context, uint64_t addr, uint32_t value);
using fn_write64 = void (*)(void *context, uint64_t addr, uint64_t value);

using fn_bb_entered = void (*)(void *context, State *state, uint64_t rva);
using fn_ext_call = void (*)(void *context, State *state, uint64_t addr);

struct verifier_context_t
{
    fn_read8 read8;
    fn_read16 read16;
    fn_read32 read32;
    fn_read64 read64;

    fn_write8 write8;
    fn_write16 write16;
    fn_write32 write32;
    fn_write64 write64;

    fn_bb_entered bb_entered;
    fn_ext_call ext_call;

    uint64_t entry_rva;
    void *context;
    State initial_reg_state;
    State final_reg_state;
};
