#include "calling_convention.hpp"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>

namespace lifted::abi
{
uint64_t get_register_value(const State &state, ABIRegister reg)
{
    switch (reg)
    {
    case ABIRegister::RAX:
        return state.gpr.rax.qword;
    case ABIRegister::RBX:
        return state.gpr.rbx.qword;
    case ABIRegister::RCX:
        return state.gpr.rcx.qword;
    case ABIRegister::RDX:
        return state.gpr.rdx.qword;
    case ABIRegister::RSI:
        return state.gpr.rsi.qword;
    case ABIRegister::RDI:
        return state.gpr.rdi.qword;
    case ABIRegister::RSP:
        return state.gpr.rsp.qword;
    case ABIRegister::RBP:
        return state.gpr.rbp.qword;
    case ABIRegister::R8:
        return state.gpr.r8.qword;
    case ABIRegister::R9:
        return state.gpr.r9.qword;
    case ABIRegister::R10:
        return state.gpr.r10.qword;
    case ABIRegister::R11:
        return state.gpr.r11.qword;
    case ABIRegister::R12:
        return state.gpr.r12.qword;
    case ABIRegister::R13:
        return state.gpr.r13.qword;
    case ABIRegister::R14:
        return state.gpr.r14.qword;
    case ABIRegister::R15:
        return state.gpr.r15.qword;
    case ABIRegister::RIP:
        return state.gpr.rip.qword;
    case ABIRegister::RFLAGS:
        return state.rflag.flat;
    default:
        llvm_unreachable("Unknown ABI register");
    }
}

llvm::ArrayRef<ABIRegister> CallingConvention::get_comparison_registers() const
{
    static std::vector<ABIRegister> combined;
    combined.clear();

    for (auto reg : getReturnRegisters())
        combined.push_back(reg);
    for (auto reg : getNonVolatileRegisters())
        combined.push_back(reg);

    return combined;
}

std::vector<std::tuple<std::string, uint64_t, uint64_t>> CallingConvention::get_divergent_registers(const State &lhs, const State &rhs) const
{
    std::vector<std::tuple<std::string, uint64_t, uint64_t>> divergences;

    for (auto reg : get_comparison_registers())
    {
        uint64_t lhs_val = get_register_value(lhs, reg);
        uint64_t rhs_val = get_register_value(rhs, reg);
        if (lhs_val == rhs_val)
            continue;

        std::string reg_name{getExtractHelperName(reg)};
        if (reg_name.starts_with("__extract_"))
            reg_name = reg_name.substr(10);
        divergences.emplace_back(reg_name, lhs_val, rhs_val);
    }

    return divergences;
}

} // namespace lifted::abi
