#pragma once

#include <cstdint>

struct reg_state_t
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;

    bool compare_full(const reg_state_t &other) const
    {
        return rax == other.rax &&
               rbx == other.rbx &&
               rcx == other.rcx &&
               rdx == other.rdx &&
               rsi == other.rsi &&
               rdi == other.rdi &&
               rsp == other.rsp &&
               rbp == other.rbp &&
               r8 == other.r8 &&
               r9 == other.r9 &&
               r10 == other.r10 &&
               r11 == other.r11 &&
               r12 == other.r12 &&
               r13 == other.r13 &&
               r14 == other.r14 &&
               r15 == other.r15 &&
               rflags == other.rflags;
    }

    bool compare_no_rsp(const reg_state_t &other) const
    {
        return rax == other.rax &&
               rbx == other.rbx &&
               rcx == other.rcx &&
               rdx == other.rdx &&
               rsi == other.rsi &&
               rdi == other.rdi &&
               rbp == other.rbp &&
               r8 == other.r8 &&
               r9 == other.r9 &&
               r10 == other.r10 &&
               r11 == other.r11 &&
               r12 == other.r12 &&
               r13 == other.r13 &&
               r14 == other.r14 &&
               r15 == other.r15 &&
               rflags == other.rflags;
    }

    // Compare System V AMD64 ABI caller-saved (volatile) registers
    // These are: RAX, RCX, RDX, RSI, RDI, R8-R11 (plus XMM0-15, not tracked here)
    // These registers may be clobbered by function calls
    bool compare_systemv_volatile(const reg_state_t &other) const
    {
        return rax == other.rax &&
               rcx == other.rcx &&
               rdx == other.rdx &&
               rsi == other.rsi &&
               rdi == other.rdi &&
               r8 == other.r8 &&
               r9 == other.r9 &&
               r10 == other.r10 &&
               r11 == other.r11;
    }

    // Compare System V AMD64 ABI callee-saved (non-volatile) registers
    // These are: RBX, RBP, R12-R15 (plus RSP, but that's handled separately)
    // Functions must preserve these across calls
    bool compare_systemv_nonvolatile(const reg_state_t &other) const
    {
        return rbx == other.rbx &&
               rbp == other.rbp &&
               r12 == other.r12 &&
               r13 == other.r13 &&
               r14 == other.r14 &&
               r15 == other.r15;
    }

    // Compare return value registers (RAX for integers, RDX for 128-bit returns)
    bool compare_return_value(const reg_state_t &other) const
    {
        return rax == other.rax && rdx == other.rdx;
    }
};