/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"
// #include "standard-intrinsics.hpp"

HELPER Memory *__lifted_ext_call(State *__restrict__, addr_t addr, Memory *);

HELPER Memory *__lifted_issue_ext_call(State *__restrict__ s, addr_t addr, Memory *m) // TODO: what to do with you
{
  __lifted_ext_call(s, addr, m);
  s->gpr.rip.qword = __remill_read_memory_64(m, s->gpr.rsp.qword);
  s->gpr.rsp.qword += 8;
  return m;
}

/// System V x64 ABI-aware external call stub.
///
/// Saves all callee-saved (non-volatile) registers, issues the opaque
/// external call, then restores non-volatile registers. This makes the
/// ABI contract visible to LLVM after inlining: LLVM can see that
/// RBX, RBP, R12-R15 are preserved across the call and optimize
/// accordingly, while volatile registers (RAX, RCX, RDX, RSI, RDI,
/// R8-R11) are treated as clobbered (opaque call may write anything).
///
/// Also pops the return address (RIP = [RSP]; RSP += 8).
HELPER Memory *__lifted_systemv_call(State *__restrict__ s, addr_t addr, Memory *m)
{
  // Save non-volatile registers
  uint64_t saved_rbx = s->gpr.rbx.qword;
  uint64_t saved_rbp = s->gpr.rbp.qword;
  uint64_t saved_r12 = s->gpr.r12.qword;
  uint64_t saved_r13 = s->gpr.r13.qword;
  uint64_t saved_r14 = s->gpr.r14.qword;
  uint64_t saved_r15 = s->gpr.r15.qword;
  uint64_t saved_rsp = s->gpr.rsp.qword;

  // Issue the opaque external call — this may clobber anything in State
  __lifted_ext_call(s, addr, m);

  // Restore non-volatile registers (ABI guarantee)
  s->gpr.rbx.qword = saved_rbx;
  s->gpr.rbp.qword = saved_rbp;
  s->gpr.r12.qword = saved_r12;
  s->gpr.r13.qword = saved_r13;
  s->gpr.r14.qword = saved_r14;
  s->gpr.r15.qword = saved_r15;
  s->gpr.rsp.qword = saved_rsp;

  // Pop return address: RIP = [RSP]; RSP += 8
  s->gpr.rip.qword = __remill_read_memory_64(m, s->gpr.rsp.qword);
  s->gpr.rsp.qword += 8;

  return m;
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