#pragma once

#include "calling_convention.hpp"

#include <array>
#include <llvm/IR/DerivedTypes.h>

namespace lifted::abi
{

    /// System V AMD64 ABI calling convention.
    ///
    /// - Integer/pointer args: RDI, RSI, RDX, RCX, R8, R9
    /// - Return: RAX (+ RDX for 128-bit)
    /// - Volatile (caller-saved): RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
    /// - Stack args begin at RSP+8 (past return address)
    /// - 16-byte stack alignment
    class SystemVx64CC final : public CallingConvention
    {
    public:
        llvm::ArrayRef<ABIRegister> getArgRegisters() const override
        {
            static constexpr std::array<ABIRegister, 6> Regs = {
                ABIRegister::RDI,
                ABIRegister::RSI,
                ABIRegister::RDX,
                ABIRegister::RCX,
                ABIRegister::R8,
                ABIRegister::R9,
            };
            return Regs;
        }

        llvm::ArrayRef<ABIRegister> getReturnRegisters() const override
        {
            static constexpr std::array<ABIRegister, 2> Regs = {
                ABIRegister::RAX,
                ABIRegister::RDX,
            };
            return Regs;
        }

        llvm::ArrayRef<ABIRegister> getVolatileRegisters() const override
        {
            // All caller-saved registers.
            // Note: RAX and RDX are also volatile, but they're handled
            // separately by return value writeback. We still include them here
            // so the EmitVolatileClobber utility can clobber everything, then
            // overwrite the return registers with actual values.
            static constexpr std::array<ABIRegister, 9> Regs = {
                ABIRegister::RAX,
                ABIRegister::RCX,
                ABIRegister::RDX,
                ABIRegister::RSI,
                ABIRegister::RDI,
                ABIRegister::R8,
                ABIRegister::R9,
                ABIRegister::R10,
                ABIRegister::R11,
            };
            return Regs;
        }

        unsigned getStackArgBaseOffset() const override
        {
            return 8; // Skip return address
        }

        unsigned getStackAlignment() const override
        {
            return 16;
        }

        llvm::FunctionType *getDefaultFunctionType(llvm::LLVMContext &Ctx) const override
        {
            // i64(i64, i64, i64, i64, i64, i64) — one i64 arg per register.
            // Conservative: extracting unused registers only costs a minor
            // optimization miss, but we still get volatile clobber + return writeback.
            llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Ctx);
            return llvm::FunctionType::get(Int64Ty,
                                           {Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int64Ty}, false);
        }
    };

} // namespace lifted::abi
