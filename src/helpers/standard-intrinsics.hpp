#pragma once

#include "types.hpp"

HELPER Memory *__remill_function_return(State *__restrict__, addr_t, Memory *memory)
{
    return memory;
}

// Implementation of the Remill flag and comparison computation intrinsics

HELPER bool __remill_flag_computation_zero(bool result, ...)
{
    return result;
}

HELPER bool __remill_flag_computation_sign(bool result, ...)
{
    return result;
}

HELPER bool __remill_flag_computation_overflow(bool result, ...)
{
    return result;
}

HELPER bool __remill_flag_computation_carry(bool result, ...)
{
    return result;
}

HELPER bool __remill_compare_sle(bool result)
{
    return result;
}

HELPER bool __remill_compare_slt(bool result)
{
    return result;
}

HELPER bool __remill_compare_sge(bool result)
{
    return result;
}

HELPER bool __remill_compare_sgt(bool result)
{
    return result;
}

HELPER bool __remill_compare_ule(bool result)
{
    return result;
}

HELPER bool __remill_compare_ult(bool result)
{
    return result;
}

HELPER bool __remill_compare_ugt(bool result)
{
    return result;
}

HELPER bool __remill_compare_uge(bool result)
{
    return result;
}

HELPER bool __remill_compare_eq(bool result)
{
    return result;
}

HELPER bool __remill_compare_neq(bool result)
{
    return result;
}

// Implementation of the Remill undefined values

HELPER uint8_t __remill_undefined_8()
{
    return 0;
}

HELPER uint16_t __remill_undefined_16()
{
    return 0;
}

HELPER uint32_t __remill_undefined_32()
{
    return 0;
}

HELPER uint64_t __remill_undefined_64()
{
    return 0;
}

// Hack for DIV

HELPER Memory *__remill_error(State *__restrict__, addr_t, Memory *)
{
    __builtin_unreachable();
}

extern "C" void *__lifted_fnc(State *__restrict__, addr_t, Memory *);

HELPER Memory *__remill_jump(State *__restrict__ state, addr_t pc, Memory *memory)
{
    // Set the program counter to the jump address.
    state->gpr.rip.qword = pc;
    // state->gpr.rsp.qword = 0xFFFFFFFF00000000; // Reset the stack pointer to a known value.

    // Return the memory pointer
    return memory;
}