
#include "types.hpp"

// Register extraction helpers
//
HELPER uint64_t __extract_rax(State *__restrict__ state)
{
    return state->gpr.rax.qword;
}
HELPER uint64_t __extract_rsi(State *__restrict__ state)
{
    return state->gpr.rsi.qword;
}
HELPER uint64_t __extract_rdi(State *__restrict__ state)
{
    return state->gpr.rdi.qword;
}
HELPER uint64_t __extract_rcx(State *__restrict__ state)
{
    return state->gpr.rcx.qword;
}
HELPER uint64_t __extract_rdx(State *__restrict__ state)
{
    return state->gpr.rdx.qword;
}
HELPER uint64_t __extract_r8(State *__restrict__ state)
{
    return state->gpr.r8.qword;
}
HELPER uint64_t __extract_r9(State *__restrict__ state)
{
    return state->gpr.r9.qword;
}
HELPER uint64_t __extract_r10(State *__restrict__ state)
{
    return state->gpr.r10.qword;
}
HELPER uint64_t __extract_r11(State *__restrict__ state)
{
    return state->gpr.r11.qword;
}
HELPER uint64_t __extract_rsp(State *__restrict__ state)
{
    return state->gpr.rsp.qword;
}

// Register store helpers
//
HELPER void __store_rax(State *__restrict__ state, uint64_t val)
{
    state->gpr.rax.qword = val;
}
HELPER void __store_rcx(State *__restrict__ state, uint64_t val)
{
    state->gpr.rcx.qword = val;
}
HELPER void __store_rdx(State *__restrict__ state, uint64_t val)
{
    state->gpr.rdx.qword = val;
}
HELPER void __store_rsi(State *__restrict__ state, uint64_t val)
{
    state->gpr.rsi.qword = val;
}
HELPER void __store_rdi(State *__restrict__ state, uint64_t val)
{
    state->gpr.rdi.qword = val;
}
HELPER void __store_r8(State *__restrict__ state, uint64_t val)
{
    state->gpr.r8.qword = val;
}
HELPER void __store_r9(State *__restrict__ state, uint64_t val)
{
    state->gpr.r9.qword = val;
}
HELPER void __store_r10(State *__restrict__ state, uint64_t val)
{
    state->gpr.r10.qword = val;
}
HELPER void __store_r11(State *__restrict__ state, uint64_t val)
{
    state->gpr.r11.qword = val;
}
HELPER void __store_rsp(State *__restrict__ state, uint64_t val)
{
    state->gpr.rsp.qword = val;
}
HELPER void __store_rip(State *__restrict__ state, uint64_t val)
{
    state->gpr.rip.qword = val;
}