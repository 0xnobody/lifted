#include "all_registers_cc.hpp"

namespace lifted::abi
{

const AllRegistersCC &AllRegistersCC::get()
{
    static const AllRegistersCC instance;
    return instance;
}

llvm::ArrayRef<ABIRegister> AllRegistersCC::getArgRegisters() const
{
    return detail::ALL_GPRS_AND_FLAGS;
}

llvm::ArrayRef<ABIRegister> AllRegistersCC::getReturnRegisters() const
{
    return detail::ALL_GPRS_AND_FLAGS;
}

llvm::ArrayRef<ABIRegister> AllRegistersCC::getVolatileRegisters() const
{
    return detail::ALL_GPRS_AND_FLAGS;
}

llvm::ArrayRef<ABIRegister> AllRegistersCC::getNonVolatileRegisters() const
{
    static constexpr std::array<ABIRegister, 0> empty{};
    return empty;
}

llvm::ArrayRef<ABIRegister> AllRegistersCC::getUnfoldRegisters() const
{
    return detail::ALL_GPRS_AND_FLAGS_AND_RIP;
}

unsigned AllRegistersCC::getStackArgBaseOffset() const
{
    return 8;
}

unsigned AllRegistersCC::getStackAlignment() const
{
    return 16;
}

llvm::StringRef AllRegistersCC::getABIName() const
{
    return "all_regs";
}

llvm::ArrayRef<ABIRegister> AllRegistersCC::get_comparison_registers() const
{
    return detail::ALL_GPRS_AND_FLAGS;
}

} // namespace lifted::abi
