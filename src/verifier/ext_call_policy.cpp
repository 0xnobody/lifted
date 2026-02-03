
#include "ext_call_policy.hpp"

namespace lifted::verif
{
    bool range_based_ext_policy::is_internal(uint64_t addr) const
    {
        for (const auto &r : internal_ranges)
        {
            if (addr >= r.start && addr < r.end)
                return true;
        }
        return false;
    }

    std::optional<ext_call_action> range_based_ext_policy::check_block_entry(
        uc_engine *uc,
        uint64_t addr,
        uint64_t from_addr) const
    {
        if (is_internal(addr))
            return std::nullopt;

        // External: assume standard call, return address is at [RSP]
        uint64_t rsp;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);

        uint64_t return_addr;
        uc_mem_read(uc, rsp, &return_addr, 8);

        // Check if returning to internal code (normal call)
        // or to external/unknown (tail call or weird control flow)
        bool normal_return = is_internal(return_addr);

        return ext_call_action{
            .target_rva = addr,
            .resume_rip = return_addr,
            .rsp_adjustment = +8, // Pop return address
            .suppress_next_bb = normal_return && (return_addr == from_addr)
            // suppress if returning to same BB we came from (unlikely but possible)
        };
    }

    bool insn_level_ext_policy::is_internal(uint64_t addr) const
    {
        for (const auto &r : internal_ranges)
        {
            if (addr >= r.start && addr < r.end)
                return true;
        }
        return false;
    }

    std::optional<ext_call_action> insn_level_ext_policy::check_transfer(
        uc_engine *uc,
        const control_transfer_t &xfer) const
    {
        // Only handle if we know the target
        if (!xfer.target_is_known)
            return std::nullopt;

        if (is_internal(xfer.target_addr))
            return std::nullopt;

        // External call detected at instruction level
        switch (xfer.type)
        {
        case control_transfer_t::type_t::CALL_REL:
        case control_transfer_t::type_t::CALL_IND:
        {
            // Skip call entirely, resume at next instruction
            uint64_t next_insn = xfer.insn_addr + xfer.insn_size;
            return ext_call_action{
                .target_rva = xfer.target_addr,
                .resume_rip = next_insn,
                .rsp_adjustment = 0, // CALL never executed, no return addr pushed
                .suppress_next_bb = true};
        }

        case control_transfer_t::type_t::JMP_REL:
        case control_transfer_t::type_t::JMP_IND:
        {
            // Tail call - return to our caller
            uint64_t rsp, ret_addr;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
            uc_mem_read(uc, rsp, &ret_addr, 8);

            return ext_call_action{
                .target_rva = xfer.target_addr,
                .resume_rip = ret_addr,
                .rsp_adjustment = +8, // Pop return address (as if returning)
                .suppress_next_bb = false};
        }

        case control_transfer_t::type_t::RET:
        {
            // RET into external code
            return ext_call_action{
                .target_rva = xfer.target_addr,
                .resume_rip = xfer.target_addr, // Let BB hook catch it
                .rsp_adjustment = 0,            // RET already adjusts RSP
                .suppress_next_bb = false};
        }

        default:
            return std::nullopt;
        }
    }

    // Helper: decode a control transfer instruction (simplified)
    // TODO: Use Capstone or similar for robust decoding
    std::optional<control_transfer_t> decode_control_transfer(
        uc_engine *uc,
        uint64_t addr,
        const uint8_t *insn,
        uint32_t size)
    {
        control_transfer_t xfer;
        xfer.insn_addr = addr;
        xfer.insn_bytes = std::span(insn, size);
        xfer.insn_size = size;
        xfer.type = control_transfer_t::type_t::UNKNOWN;
        xfer.target_is_known = false;

        if (size == 0)
            return std::nullopt;

        // CALL rel32 (E8 cd)
        if (insn[0] == 0xE8 && size >= 5)
        {
            xfer.type = control_transfer_t::type_t::CALL_REL;
            int32_t rel = *reinterpret_cast<const int32_t *>(&insn[1]);
            xfer.target_addr = addr + 5 + rel;
            xfer.insn_size = 5;
            xfer.target_is_known = true;
            return xfer;
        }

        // JMP rel32 (E9 cd)
        if (insn[0] == 0xE9 && size >= 5)
        {
            xfer.type = control_transfer_t::type_t::JMP_REL;
            int32_t rel = *reinterpret_cast<const int32_t *>(&insn[1]);
            xfer.target_addr = addr + 5 + rel;
            xfer.insn_size = 5;
            xfer.target_is_known = true;
            return xfer;
        }

        // JMP rel8 (EB cb)
        if (insn[0] == 0xEB && size >= 2)
        {
            xfer.type = control_transfer_t::type_t::JMP_REL;
            int8_t rel = *reinterpret_cast<const int8_t *>(&insn[1]);
            xfer.target_addr = addr + 2 + rel;
            xfer.insn_size = 2;
            xfer.target_is_known = true;
            return xfer;
        }

        // RET (C3)
        if (insn[0] == 0xC3)
        {
            xfer.type = control_transfer_t::type_t::RET;
            xfer.insn_size = 1;
            // Read return address from stack
            uint64_t rsp;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
            uc_mem_read(uc, rsp, &xfer.target_addr, 8);
            xfer.target_is_known = true;
            return xfer;
        }

        // RET imm16 (C2 iw)
        if (insn[0] == 0xC2 && size >= 3)
        {
            xfer.type = control_transfer_t::type_t::RET;
            xfer.insn_size = 3;
            uint64_t rsp;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
            uc_mem_read(uc, rsp, &xfer.target_addr, 8);
            xfer.target_is_known = true;
            return xfer;
        }

        // FF /2 - CALL r/m64 (indirect call)
        // FF /4 - JMP r/m64 (indirect jump)
        if (insn[0] == 0xFF && size >= 2)
        {
            uint8_t modrm = insn[1];
            uint8_t reg = (modrm >> 3) & 0x7;

            if (reg == 2)
            { // CALL r/m64
                xfer.type = control_transfer_t::type_t::CALL_IND;
                // For indirect calls, we'd need to decode ModR/M to get target
                // For now, mark as unknown - user can read RIP after instruction
                xfer.target_is_known = false;
                return xfer;
            }
            else if (reg == 4)
            { // JMP r/m64
                xfer.type = control_transfer_t::type_t::JMP_IND;
                xfer.target_is_known = false;
                return xfer;
            }
        }

        return std::nullopt; // Not a recognized control transfer
    }

}