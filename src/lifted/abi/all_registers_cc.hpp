#pragma once

#include "calling_convention.hpp"

namespace lifted::abi
{

    /// Pseudo-ABI for internal lifted functions where the full architectural state
    /// remains semantically relevant. Models all GPRs plus packed flags.
    class AllRegistersCC final : public CallingConvention
    {
      public:
        static const AllRegistersCC &get();

        llvm::ArrayRef<ABIRegister> getArgRegisters() const override;
        llvm::ArrayRef<ABIRegister> getReturnRegisters() const override;
        llvm::ArrayRef<ABIRegister> getVolatileRegisters() const override;
        llvm::ArrayRef<ABIRegister> getNonVolatileRegisters() const override;
        llvm::ArrayRef<ABIRegister> getUnfoldRegisters() const override;
        unsigned getStackArgBaseOffset() const override;
        unsigned getStackAlignment() const override;
        llvm::StringRef getABIName() const override;
        llvm::ArrayRef<ABIRegister> get_comparison_registers() const override;
    };

} // namespace lifted::abi
