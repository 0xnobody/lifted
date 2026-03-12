#pragma once

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/DenseMapInfo.h>
#include <llvm/ADT/StringRef.h>

#include <optional>

#include <remill/Arch/X86/Runtime/State.h>

#include <array>
#include <cstdint>
#include <tuple>
#include <vector>

namespace llvm
{
class Type;
} // namespace llvm

namespace lifted::abi
{

enum class ABIRegister
{
    // Volatile (caller-saved)
    RAX,
    RCX,
    RDX,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    RSP,
    // Instruction pointer is part of the unfolded internal state contract,
    // but not a general-purpose argument or preserved register.
    RIP,
    RFLAGS,
    // Non-volatile (callee-saved)
    RBX,
    RBP,
    R12,
    R13,
    R14,
    R15,
};

} // namespace lifted::abi

template <>
struct llvm::DenseMapInfo<lifted::abi::ABIRegister>
{
    using T = lifted::abi::ABIRegister;
    static inline T getEmptyKey() { return static_cast<T>(~0U); }
    static inline T getTombstoneKey() { return static_cast<T>(~0U - 1); }
    static unsigned getHashValue(T Val) { return static_cast<unsigned>(Val); }
    static bool isEqual(T LHS, T RHS) { return LHS == RHS; }
};

namespace lifted::abi
{

inline llvm::StringRef getExtractHelperName(ABIRegister Reg)
{
    switch (Reg)
    {
    case ABIRegister::RAX:
        return "__extract_rax";
    case ABIRegister::RCX:
        return "__extract_rcx";
    case ABIRegister::RDX:
        return "__extract_rdx";
    case ABIRegister::RSI:
        return "__extract_rsi";
    case ABIRegister::RDI:
        return "__extract_rdi";
    case ABIRegister::R8:
        return "__extract_r8";
    case ABIRegister::R9:
        return "__extract_r9";
    case ABIRegister::R10:
        return "__extract_r10";
    case ABIRegister::R11:
        return "__extract_r11";
    case ABIRegister::RSP:
        return "__extract_rsp";
    case ABIRegister::RIP:
        return "__extract_rip";
    case ABIRegister::RFLAGS:
        return "__extract_rflags";
    case ABIRegister::RBX:
        return "__extract_rbx";
    case ABIRegister::RBP:
        return "__extract_rbp";
    case ABIRegister::R12:
        return "__extract_r12";
    case ABIRegister::R13:
        return "__extract_r13";
    case ABIRegister::R14:
        return "__extract_r14";
    case ABIRegister::R15:
        return "__extract_r15";
    }
    llvm_unreachable("Unknown ABI register");
}

namespace detail
{
constexpr std::array<ABIRegister, 16> ALL_GPRS = {
    ABIRegister::RAX, ABIRegister::RBX, ABIRegister::RCX,
    ABIRegister::RDX, ABIRegister::RSI, ABIRegister::RDI,
    ABIRegister::RSP, ABIRegister::RBP, ABIRegister::R8,
    ABIRegister::R9, ABIRegister::R10, ABIRegister::R11,
    ABIRegister::R12, ABIRegister::R13, ABIRegister::R14,
    ABIRegister::R15};

constexpr std::array<ABIRegister, 17> ALL_GPRS_AND_FLAGS = {
    ABIRegister::RAX, ABIRegister::RBX, ABIRegister::RCX,
    ABIRegister::RDX, ABIRegister::RSI, ABIRegister::RDI,
    ABIRegister::RSP, ABIRegister::RBP, ABIRegister::R8,
    ABIRegister::R9, ABIRegister::R10, ABIRegister::R11,
    ABIRegister::R12, ABIRegister::R13, ABIRegister::R14,
    ABIRegister::R15, ABIRegister::RFLAGS};

constexpr std::array<ABIRegister, 18> ALL_GPRS_AND_FLAGS_AND_RIP = {
    ABIRegister::RAX, ABIRegister::RBX, ABIRegister::RCX,
    ABIRegister::RDX, ABIRegister::RSI, ABIRegister::RDI,
    ABIRegister::RSP, ABIRegister::RBP, ABIRegister::R8,
    ABIRegister::R9, ABIRegister::R10, ABIRegister::R11,
    ABIRegister::R12, ABIRegister::R13, ABIRegister::R14,
    ABIRegister::R15, ABIRegister::RFLAGS, ABIRegister::RIP};
} // namespace detail

uint64_t get_register_value(const State &state, ABIRegister reg);

inline llvm::StringRef getStoreHelperName(ABIRegister Reg)
{
    switch (Reg)
    {
    case ABIRegister::RAX:
        return "__store_rax";
    case ABIRegister::RCX:
        return "__store_rcx";
    case ABIRegister::RDX:
        return "__store_rdx";
    case ABIRegister::RSI:
        return "__store_rsi";
    case ABIRegister::RDI:
        return "__store_rdi";
    case ABIRegister::R8:
        return "__store_r8";
    case ABIRegister::R9:
        return "__store_r9";
    case ABIRegister::R10:
        return "__store_r10";
    case ABIRegister::R11:
        return "__store_r11";
    case ABIRegister::RSP:
        return "__store_rsp";
    case ABIRegister::RIP:
        return "__store_rip";
    case ABIRegister::RFLAGS:
        return "__store_rflags";
    case ABIRegister::RBX:
        return "__store_rbx";
    case ABIRegister::RBP:
        return "__store_rbp";
    case ABIRegister::R12:
        return "__store_r12";
    case ABIRegister::R13:
        return "__store_r13";
    case ABIRegister::R14:
        return "__store_r14";
    case ABIRegister::R15:
        return "__store_r15";
    }
    llvm_unreachable("Unknown ABI register");
}

struct CallingConvention
{
    virtual ~CallingConvention() = default;

    virtual llvm::ArrayRef<ABIRegister> getArgRegisters() const = 0;
    virtual llvm::ArrayRef<ABIRegister> getReturnRegisters() const = 0;
    virtual llvm::ArrayRef<ABIRegister> getVolatileRegisters() const = 0;
    virtual llvm::ArrayRef<ABIRegister> getNonVolatileRegisters() const = 0;

    virtual llvm::ArrayRef<ABIRegister> getUnfoldRegisters() const
    {
        return getVolatileRegisters();
    }

    virtual llvm::StringRef getABIName() const = 0;

    std::optional<unsigned> getUnfoldParamIndex(ABIRegister Reg) const
    {
        auto regs = getUnfoldRegisters();
        for (unsigned i = 0, n = static_cast<unsigned>(regs.size()); i < n; ++i)
            if (regs[i] == Reg)
                return i;
        return std::nullopt;
    }

    std::optional<ABIRegister> getRegisterForUnfoldParam(unsigned ParamIdx) const
    {
        auto regs = getUnfoldRegisters();
        if (ParamIdx < regs.size())
            return regs[ParamIdx];
        return std::nullopt;
    }

    virtual unsigned getStackArgBaseOffset() const = 0;
    virtual unsigned getStackAlignment() const = 0;

    virtual llvm::ArrayRef<ABIRegister> get_comparison_registers() const;
    virtual std::vector<std::tuple<std::string, uint64_t, uint64_t>> get_divergent_registers(const State &lhs, const State &rhs) const;
};

} // namespace lifted::abi
