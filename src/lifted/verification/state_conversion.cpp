#include "state_conversion.hpp"

#include <llvm/Support/Error.h>

#include <sstream>

namespace lifted::verification
{

    // Helper to create error messages
    static llvm::Error uc_error(const char *operation, uc_err err)
    {
        std::ostringstream msg;
        msg << operation << " failed: " << uc_strerror(err);
        return llvm::make_error<llvm::StringError>(msg.str(), llvm::inconvertibleErrorCode());
    }

    llvm::Error state_to_unicorn(const State &state, uc_engine *uc)
    {
        // Write all GPRs to Unicorn
        struct RegMapping
        {
            int uc_reg;
            uint64_t value;
        };

        RegMapping mappings[] = {
            {UC_X86_REG_RAX, state.gpr.rax.qword},
            {UC_X86_REG_RBX, state.gpr.rbx.qword},
            {UC_X86_REG_RCX, state.gpr.rcx.qword},
            {UC_X86_REG_RDX, state.gpr.rdx.qword},
            {UC_X86_REG_RSI, state.gpr.rsi.qword},
            {UC_X86_REG_RDI, state.gpr.rdi.qword},
            {UC_X86_REG_RSP, state.gpr.rsp.qword},
            {UC_X86_REG_RBP, state.gpr.rbp.qword},
            {UC_X86_REG_R8, state.gpr.r8.qword},
            {UC_X86_REG_R9, state.gpr.r9.qword},
            {UC_X86_REG_R10, state.gpr.r10.qword},
            {UC_X86_REG_R11, state.gpr.r11.qword},
            {UC_X86_REG_R12, state.gpr.r12.qword},
            {UC_X86_REG_R13, state.gpr.r13.qword},
            {UC_X86_REG_R14, state.gpr.r14.qword},
            {UC_X86_REG_R15, state.gpr.r15.qword},
            {UC_X86_REG_RIP, state.gpr.rip.qword},
            {UC_X86_REG_EFLAGS, state.rflag.flat},
        };

        for (const auto &mapping : mappings)
        {
            uc_err err = uc_reg_write(uc, mapping.uc_reg, &mapping.value);
            if (err != UC_ERR_OK)
            {
                return uc_error("uc_reg_write", err);
            }
        }

        return llvm::Error::success();
    }

    State unicorn_to_state(uc_engine *uc)
    {
        State state{};

        // Read all GPRs from Unicorn
        uc_reg_read(uc, UC_X86_REG_RAX, &state.gpr.rax.qword);
        uc_reg_read(uc, UC_X86_REG_RBX, &state.gpr.rbx.qword);
        uc_reg_read(uc, UC_X86_REG_RCX, &state.gpr.rcx.qword);
        uc_reg_read(uc, UC_X86_REG_RDX, &state.gpr.rdx.qword);
        uc_reg_read(uc, UC_X86_REG_RSI, &state.gpr.rsi.qword);
        uc_reg_read(uc, UC_X86_REG_RDI, &state.gpr.rdi.qword);
        uc_reg_read(uc, UC_X86_REG_RSP, &state.gpr.rsp.qword);
        uc_reg_read(uc, UC_X86_REG_RBP, &state.gpr.rbp.qword);
        uc_reg_read(uc, UC_X86_REG_R8, &state.gpr.r8.qword);
        uc_reg_read(uc, UC_X86_REG_R9, &state.gpr.r9.qword);
        uc_reg_read(uc, UC_X86_REG_R10, &state.gpr.r10.qword);
        uc_reg_read(uc, UC_X86_REG_R11, &state.gpr.r11.qword);
        uc_reg_read(uc, UC_X86_REG_R12, &state.gpr.r12.qword);
        uc_reg_read(uc, UC_X86_REG_R13, &state.gpr.r13.qword);
        uc_reg_read(uc, UC_X86_REG_R14, &state.gpr.r14.qword);
        uc_reg_read(uc, UC_X86_REG_R15, &state.gpr.r15.qword);
        uc_reg_read(uc, UC_X86_REG_RIP, &state.gpr.rip.qword);
        uc_reg_read(uc, UC_X86_REG_EFLAGS, &state.rflag.flat);

        return state;
    }
} // namespace lifted::verification
