/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"
// #include "standard-intrinsics.hpp"

HELPER Memory *__lifted_ext_call(State *__restrict__, addr_t addr, Memory *);
HELPER Memory *__lifted_recursive_call(State *__restrict__, addr_t addr, Memory *);

HELPER void __lifted_make_resident()
{
    (void)__lifted_ext_call(nullptr, 0, nullptr);
    (void)__lifted_recursive_call(nullptr, 0, nullptr);
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