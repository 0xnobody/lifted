#pragma once

#include <cstdint>

#include <remill/Arch/X86/Runtime/State.h>

#define LOAD_BASE 0x7ffff7000000ULL

using fn_read8 = bool (*)(void *context, uint64_t addr, uint8_t &value);
using fn_read16 = bool (*)(void *context, uint64_t addr, uint16_t &value);
using fn_read32 = bool (*)(void *context, uint64_t addr, uint32_t &value);
using fn_read64 = bool (*)(void *context, uint64_t addr, uint64_t &value);

using fn_write8 = bool (*)(void *context, uint64_t addr, uint8_t value);
using fn_write16 = bool (*)(void *context, uint64_t addr, uint16_t value);
using fn_write32 = bool (*)(void *context, uint64_t addr, uint32_t value);
using fn_write64 = bool (*)(void *context, uint64_t addr, uint64_t value);

using fn_bb_entered = bool (*)(void *context, State *state, uint64_t rva);
using fn_ext_call = bool (*)(void *context, State *state, uint64_t addr);

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
