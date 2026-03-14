#pragma once

#include "calling_convention.hpp"

#include <array>

namespace lifted::abi
{

class SystemVx64CC final : public CallingConvention
{
  public:
    static const SystemVx64CC &get()
    {
        static const SystemVx64CC instance;
        return instance;
    }

    using CallingConvention::getArgRegisters;
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
        static constexpr std::array<ABIRegister, 10> Regs = {
            ABIRegister::RAX,
            ABIRegister::RCX,
            ABIRegister::RDX,
            ABIRegister::RSI,
            ABIRegister::RDI,
            ABIRegister::R8,
            ABIRegister::R9,
            ABIRegister::R10,
            ABIRegister::R11,
            ABIRegister::RFLAGS,
        };
        return Regs;
    }

    llvm::ArrayRef<ABIRegister> getNonVolatileRegisters() const override
    {
        static constexpr std::array<ABIRegister, 6> Regs = {
            ABIRegister::RBX,
            ABIRegister::RBP,
            ABIRegister::R12,
            ABIRegister::R13,
            ABIRegister::R14,
            ABIRegister::R15,
        };
        return Regs;
    }

    unsigned getStackArgBaseOffset() const override
    {
        return 8;
    }

    unsigned getStackAlignment() const override
    {
        return 16;
    }

    llvm::StringRef getABIName() const override
    {
        return "systemv_x64";
    }
};

} // namespace lifted::abi
