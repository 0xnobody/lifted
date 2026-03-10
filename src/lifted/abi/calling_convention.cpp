#include "calling_convention.hpp"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>

namespace lifted::abi
{

    unsigned CallingConvention::getNumReturnRegisters(llvm::Type *RetTy) const
    {
        if (RetTy->isVoidTy())
            return 0;

        // Struct returns like {i64, i64} use two registers.
        if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(RetTy))
        {
            unsigned NumElements = StructTy->getNumElements();
            unsigned MaxRegs = getReturnRegisters().size();
            return std::min(NumElements, MaxRegs);
        }

        // Scalar returns use one register.
        return 1;
    }

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
        }
        llvm_unreachable("Unknown ABI register");
    }

    bool CallingConvention::compare_return_value(const State &lhs, const State &rhs) const
    {
        for (auto reg : getReturnRegisters())
        {
            if (get_register_value(lhs, reg) != get_register_value(rhs, reg))
            {
                return false;
            }
        }
        return true;
    }

    bool CallingConvention::compare_preserved_registers(const State &lhs, const State &rhs) const
    {
        for (auto reg : getNonVolatileRegisters())
        {
            if (get_register_value(lhs, reg) != get_register_value(rhs, reg))
            {
                return false;
            }
        }
        return true;
    }

    llvm::ArrayRef<ABIRegister> CallingConvention::get_comparison_registers() const
    {
        // Default: return + preserved registers
        // Subclasses can override to include more (e.g., AllRegistersCC)
        static std::vector<ABIRegister> combined;
        combined.clear();

        for (auto reg : getReturnRegisters())
        {
            combined.push_back(reg);
        }
        for (auto reg : getNonVolatileRegisters())
        {
            combined.push_back(reg);
        }

        return combined;
    }

    std::vector<std::tuple<std::string, uint64_t, uint64_t>>
    CallingConvention::get_divergent_registers(const State &lhs, const State &rhs) const
    {
        std::vector<std::tuple<std::string, uint64_t, uint64_t>> divergences;

        for (auto reg : get_comparison_registers())
        {
            uint64_t lhs_val = get_register_value(lhs, reg);
            uint64_t rhs_val = get_register_value(rhs, reg);

            if (lhs_val != rhs_val)
            {
                std::string reg_name{getExtractHelperName(reg)};
                // Strip __extract_ prefix to get register name
                if (reg_name.starts_with("__extract_"))
                {
                    reg_name = reg_name.substr(10);
                }
                divergences.emplace_back(reg_name, lhs_val, rhs_val);
            }
        }

        return divergences;
    }

    // AllRegistersCC implementation

    llvm::ArrayRef<ABIRegister> AllRegistersCC::getArgRegisters() const
    {
        // No args for this pseudo-ABI
        static constexpr std::array<ABIRegister, 0> empty{};
        return empty;
    }

    llvm::ArrayRef<ABIRegister> AllRegistersCC::getReturnRegisters() const
    {
        // Return all GPRs (interpret as "return" for comparison purposes)
        return detail::ALL_GPRS;
    }

    llvm::ArrayRef<ABIRegister> AllRegistersCC::getVolatileRegisters() const
    {
        // All registers are "volatile" for this pseudo-ABI
        return detail::ALL_GPRS;
    }

    llvm::ArrayRef<ABIRegister> AllRegistersCC::getNonVolatileRegisters() const
    {
        // No preserved registers for this pseudo-ABI
        static constexpr std::array<ABIRegister, 0> empty{};
        return empty;
    }

    llvm::StringRef AllRegistersCC::getCallStubName() const
    {
        return "__lifted_allregs_call"; // Unused
    }

    llvm::StringRef AllRegistersCC::getRecursiveCallStubName() const
    {
        return "__lifted_allregs_recursive_call"; // Unused
    }

    unsigned AllRegistersCC::getStackArgBaseOffset() const
    {
        return 8; // Unused
    }

    unsigned AllRegistersCC::getStackAlignment() const
    {
        return 16; // Standard
    }

    llvm::FunctionType *AllRegistersCC::getDefaultFunctionType(llvm::LLVMContext &Ctx) const
    {
        // Unused - return simple void()
        return llvm::FunctionType::get(llvm::Type::getVoidTy(Ctx), {}, false);
    }

    llvm::ArrayRef<ABIRegister> AllRegistersCC::get_comparison_registers() const
    {
        // Compare all GPRs
        return detail::ALL_GPRS;
    }

} // namespace lifted::abi
