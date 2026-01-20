
#include "types.hpp"

// Call-site helpers
//
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
HELPER uint64_t __extract_rsp(State *__restrict__ state)
{
    return state->gpr.rsp.qword;
}

HELPER void __store_rsp(State *__restrict__ state, uint64_t rsp)
{
    state->gpr.rsp.qword = rsp;
}
HELPER void __store_rax(State *__restrict__ state, uint64_t rax)
{
    state->gpr.rax.qword = rax;
}