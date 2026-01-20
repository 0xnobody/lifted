#include <cstdint>
#include <cstring>

#include "types.hpp"

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
    state.gpr.rip.qword = 0;

    // Execute the lifted function
    memory = __lifted_function(state, memory);

    // Load updated GPRs
    *rax = state.gpr.rax.qword;

    // Return the memory pointer
    return memory;
}