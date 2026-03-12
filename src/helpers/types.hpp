#pragma once

#include <cstdint>
#include <remill/Arch/Runtime/Types.h>
#include <remill/Arch/X86/Runtime/State.h>

using rptr16 = uint128_t *__restrict__;
using rptr8 = uint64_t *__restrict__;
using rptr4 = uint32_t *__restrict__;
using rptr1 = uint8_t *__restrict__;

// NOTE: We disable tail calls because it can cause the DSEPass to make false assumptions
#define HELPER_NOINLINE extern "C" __attribute__((disable_tail_calls))
#define HELPER HELPER_NOINLINE __attribute__((always_inline))

extern "C" Memory *__remill_function(State &state, addr_t address, Memory *memory);

extern "C" Memory *__lifted_function(State &state, Memory *memory);

HELPER uint8_t __remill_read_memory_8(Memory *m, addr_t a);
HELPER uint16_t __remill_read_memory_16(Memory *m, addr_t a);
HELPER uint32_t __remill_read_memory_32(Memory *m, addr_t a);
HELPER uint64_t __remill_read_memory_64(Memory *m, addr_t a);
HELPER Memory *__remill_write_memory_8(Memory *m, addr_t a, uint8_t v);
HELPER Memory *__remill_write_memory_16(Memory *m, addr_t a, uint16_t v);
HELPER Memory *__remill_write_memory_32(Memory *m, addr_t a, uint32_t v);
HELPER Memory *__remill_write_memory_64(Memory *m, addr_t a, uint64_t v);

HELPER __attribute__((pure)) Memory *__lifted_bb_entered(State state, addr_t a, Memory *m);
HELPER Memory *__lifted_verifier_ext_call(State *state, addr_t pc, Memory *m, uint64_t annotation_id);
