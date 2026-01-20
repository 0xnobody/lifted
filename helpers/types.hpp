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
