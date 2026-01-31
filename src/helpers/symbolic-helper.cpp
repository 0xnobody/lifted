#include "klee-intrinsics.hpp"
#include "types.hpp"

HELPER uint64_t __extract_rip(State *__restrict__ state)
{
    return state->gpr.rip.qword;
}

extern "C" uint64_t __slice_rip(State state, uint64_t rsp, addr_t curr_pc, Memory *__restrict__ memory)
{
    State S = {};

    S.gpr.rax = state.gpr.rax;
    S.gpr.rbx = state.gpr.rbx;
    S.gpr.rcx = state.gpr.rcx;
    S.gpr.rdx = state.gpr.rdx;
    S.gpr.rsi = state.gpr.rsi;
    S.gpr.rdi = state.gpr.rdi;
    S.gpr.rbp = state.gpr.rbp;
    S.gpr.rsp.qword = rsp;
    S.gpr.r8 = state.gpr.r8;
    S.gpr.r9 = state.gpr.r9;
    S.gpr.r10 = state.gpr.r10;
    S.gpr.r11 = state.gpr.r11;
    S.gpr.r12 = state.gpr.r12;
    S.gpr.r13 = state.gpr.r13;
    S.gpr.r14 = state.gpr.r14;
    S.gpr.r15 = state.gpr.r15;

    S.gpr.rip.qword = curr_pc;

    S.aflag.af = state.aflag.af;
    S.aflag.cf = state.aflag.cf;
    S.aflag.pf = state.aflag.pf;
    S.aflag.zf = state.aflag.zf;
    S.aflag.sf = state.aflag.sf;
    S.aflag.of = state.aflag.of;
    S.aflag.df = state.aflag.df;

    __remill_function(S, curr_pc, memory);

    return S.gpr.rip.qword;
}

/*
void klee_test()
{
    uint64_t rdi, rsi, rcx, rdx, rsp;
    klee_make_symbolic(&rdi, sizeof(rdi), "rdi");
    klee_make_symbolic(&rsi, sizeof(rsi), "rsi");
    klee_make_symbolic(&rcx, sizeof(rcx), "rcx");
    klee_make_symbolic(&rdx, sizeof(rdx), "rdx");
    klee_make_symbolic(&rsp, sizeof(rsp), "rsp");

    uint64_t rip;
    __extract_rip(nullptr, rcx, rdx, rsp, rsi, rdi, &rip);

    klee_print_expr("rip=", rip);
}

int main(int argc, char **argv)
{
    klee_test();
    return 0;
}
*/