#pragma once

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/DenseMapInfo.h>
#include <llvm/ADT/StringRef.h>

#include <remill/Arch/X86/Runtime/State.h>

#include <array>
#include <cstdint>
#include <tuple>
#include <vector>

namespace llvm
{
    class Type;
    class FunctionType;
    class LLVMContext;
}

namespace lifted::abi
{

    /// Registers used for argument passing, return values, and volatile clobbering.
    /// Each value corresponds to a pair of __extract_<name> / __store_<name> helpers
    /// in state-utils.
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
        // Non-volatile (callee-saved)
        RBX,
        RBP,
        R12,
        R13,
        R14,
        R15,
    };

} // namespace lifted::abi

// DenseMapInfo specialization so ABIRegister can be used in SmallDenseSet/DenseMap.
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

    /// Returns the name of the __extract_<reg> helper for a given ABI register.
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
        // All x86-64 GPRs for full register comparison
        constexpr std::array<ABIRegister, 16> ALL_GPRS = {
            ABIRegister::RAX, ABIRegister::RBX, ABIRegister::RCX,
            ABIRegister::RDX, ABIRegister::RSI, ABIRegister::RDI,
            ABIRegister::RSP, ABIRegister::RBP, ABIRegister::R8,
            ABIRegister::R9, ABIRegister::R10, ABIRegister::R11,
            ABIRegister::R12, ABIRegister::R13, ABIRegister::R14,
            ABIRegister::R15};
    } // namespace detail

    /// Get register value from Remill State structure.
    uint64_t get_register_value(const State &state, ABIRegister reg);

    /// Returns the name of the __store_<reg> helper for a given ABI register.
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

    /// Abstract calling convention interface.
    ///
    /// Describes how arguments are passed, return values are received, and which
    /// registers are clobbered across function calls. Implementations exist for
    /// specific ABIs (System V x64, Win64, etc.).
    struct CallingConvention
    {
        virtual ~CallingConvention() = default;

        /// Ordered list of registers used for integer/pointer argument passing.
        /// Arguments beyond this count are passed on the stack.
        virtual llvm::ArrayRef<ABIRegister> getArgRegisters() const = 0;

        /// Registers used for return values. Typically {RAX} for scalar returns,
        /// {RAX, RDX} for 128-bit returns.
        virtual llvm::ArrayRef<ABIRegister> getReturnRegisters() const = 0;

        /// Caller-saved registers that are clobbered across a function call.
        /// After a call, these hold arbitrary values.
        virtual llvm::ArrayRef<ABIRegister> getVolatileRegisters() const = 0;

        /// Callee-saved registers that are preserved across a function call.
        /// The ABI stub saves these before the call and restores them after.
        virtual llvm::ArrayRef<ABIRegister> getNonVolatileRegisters() const = 0;

        /// Returns the name of the ABI-specific external-call stub helper.
        /// E.g. "__lifted_systemv_call" for System V x64.
        /// The stub saves non-volatile regs, calls __lifted_ext_call, restores them,
        /// and pops the return address.
        virtual llvm::StringRef getCallStubName() const = 0;

        /// Returns the name of the ABI-specific recursive-call stub helper.
        /// E.g. "__lifted_systemv_recursive_call" for System V x64.
        /// The stub mirrors getCallStubName() but routes through
        /// __lifted_recursive_call instead of __lifted_ext_call.
        virtual llvm::StringRef getRecursiveCallStubName() const = 0;

        /// Base offset from RSP where stack arguments begin.
        /// System V: 8 (skip return address)
        /// Win64: 40 (32-byte shadow space + 8 return address)
        virtual unsigned getStackArgBaseOffset() const = 0;

        /// Required stack alignment in bytes (typically 16).
        virtual unsigned getStackAlignment() const = 0;

        /// How many return registers are actually used for a given function type.
        /// Default: 1 for scalar, 2 for {i64, i64} aggregates.
        virtual unsigned getNumReturnRegisters(llvm::Type *RetTy) const;

        /// Returns a default function type to use when no defs module entry exists.
        /// For System V: i64(i64, i64, i64, i64, i64, i64) — all 6 arg registers.
        /// This is conservative: extracting registers that aren't actually used
        /// by the callee just prevents dead-store elimination on those registers,
        /// but we still get volatile clobber and return writeback benefits.
        virtual llvm::FunctionType *getDefaultFunctionType(llvm::LLVMContext &Ctx) const = 0;

        /// Compare return value registers between two states.
        /// Returns true if all return registers match.
        virtual bool compare_return_value(const State &lhs, const State &rhs) const;

        /// Compare preserved (callee-saved) registers between two states.
        /// Returns true if all preserved registers match.
        virtual bool compare_preserved_registers(const State &lhs, const State &rhs) const;

        /// Get list of all registers this ABI cares about for comparison.
        /// Default: return + preserved registers.
        virtual llvm::ArrayRef<ABIRegister> get_comparison_registers() const;

        /// Get detailed list of divergent registers.
        /// Returns vector of (register_name, lhs_value, rhs_value) tuples.
        virtual std::vector<std::tuple<std::string, uint64_t, uint64_t>>
        get_divergent_registers(const State &lhs, const State &rhs) const;
    };

    /// Special ABI for comparing ALL x86-64 general-purpose registers.
    /// Useful for debugging or when ABI-specific comparison is too narrow.
    class AllRegistersCC final : public CallingConvention
    {
    public:
        // CallingConvention interface (most return empty/defaults)
        llvm::ArrayRef<ABIRegister> getArgRegisters() const override;
        llvm::ArrayRef<ABIRegister> getReturnRegisters() const override;
        llvm::ArrayRef<ABIRegister> getVolatileRegisters() const override;
        llvm::ArrayRef<ABIRegister> getNonVolatileRegisters() const override;
        llvm::StringRef getCallStubName() const override;
        llvm::StringRef getRecursiveCallStubName() const override;
        unsigned getStackArgBaseOffset() const override;
        unsigned getStackAlignment() const override;
        llvm::FunctionType *getDefaultFunctionType(llvm::LLVMContext &Ctx) const override;

        // Comparison methods (uses all GPRs)
        llvm::ArrayRef<ABIRegister> get_comparison_registers() const override;
    };

} // namespace lifted::abi
