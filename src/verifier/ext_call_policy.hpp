#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>
#include <unicorn/unicorn.h>

#include <lifted/shared.hpp> // For mem_range_t, paged_memory_state

// Information about a control transfer instruction
struct control_transfer_t
{
    uint64_t insn_addr;                  // Address of the instruction
    std::span<const uint8_t> insn_bytes; // Raw instruction bytes
    uint32_t insn_size;                  // Size of the instruction

    enum class type_t
    {
        CALL_REL, // E8: CALL rel32
        CALL_IND, // FF /2: CALL r/m64
        JMP_REL,  // E9/EB: JMP rel32/rel8
        JMP_IND,  // FF /4: JMP r/m64
        RET,      // C3/C2: RET / RET imm16
        UNKNOWN
    };
    type_t type = type_t::UNKNOWN;

    uint64_t target_addr = 0;     // Computed target (for direct transfers or resolved indirect)
    bool target_is_known = false; // True if target_addr is valid
};

// Recorded external call (for comparison between baseline and test)
struct ext_call_record
{
    uint64_t target_rva; // The external function called
    // Future: argument values, stack state hash, etc.
};

// What the policy decides when handling an external call
struct ext_call_action
{
    uint64_t target_rva;    // What to record as the external call target
    uint64_t resume_rip;    // Where to continue execution
    int64_t rsp_adjustment; // How to adjust RSP (e.g., 0 for skipped CALL, +8 for "returning")

    // If true, suppress recording a new BB when we resume at resume_rip
    // (used when external call returns to the same logical BB)
    bool suppress_next_bb = false;

    // Future: mock_rax, captured_args, etc.
};

// User-implemented policy for detecting and handling external calls
struct ext_call_policy
{
    virtual ~ext_call_policy() = default;

    // Configuration: should the instruction-level hook be enabled?
    // If false, only BB-level detection (check_block_entry) is used.
    // If true, check_transfer is called for each control transfer instruction.
    // Default is false for performance; set true if you need call-site inspection.
    virtual bool use_instruction_hook() const { return false; }

    // Called for control transfer instructions (call, jmp, ret) when instruction hook is enabled.
    // Return nullopt if this is NOT an external call (proceed normally).
    // Return ext_call_action if this IS external (skip and resume as specified).
    //
    // This allows inspection of the call site (instruction bytes, pattern matching).
    virtual std::optional<ext_call_action> check_transfer(
        uc_engine *uc,
        const control_transfer_t &transfer) const
    {
        return std::nullopt;
    }

    // Called when entering a basic block.
    // from_addr: the last internal instruction address (for context).
    // Return nullopt if this block is internal (proceed normally).
    // Return ext_call_action if this block is external (skip and resume as specified).
    //
    // This is simpler but doesn't allow call-site inspection.
    virtual std::optional<ext_call_action> check_block_entry(
        uc_engine *uc,
        uint64_t addr,
        uint64_t from_addr) const
    {
        return std::nullopt;
    }
};

// Simple range-based policy: addresses outside internal_ranges are external
struct range_based_ext_policy : ext_call_policy
{
    std::vector<mem_range_t> internal_ranges;

    explicit range_based_ext_policy(std::vector<mem_range_t> ranges)
        : internal_ranges(std::move(ranges))
    {
    }

    bool is_internal(uint64_t addr) const;

    std::optional<ext_call_action> check_block_entry(
        uc_engine *uc,
        uint64_t addr,
        uint64_t from_addr) const override;
};

// Instruction-hook based policy example (for obfuscators needing call-site inspection)
struct insn_level_ext_policy : ext_call_policy
{
    std::vector<mem_range_t> internal_ranges;

    explicit insn_level_ext_policy(std::vector<mem_range_t> ranges)
        : internal_ranges(std::move(ranges))
    {
    }

    bool use_instruction_hook() const override { return true; }

    bool is_internal(uint64_t addr) const;

    std::optional<ext_call_action> check_transfer(
        uc_engine *uc,
        const control_transfer_t &xfer) const override;
};

// Helper: decode a control transfer instruction (simplified)
// TODO: Use Capstone or similar for robust decoding
std::optional<control_transfer_t> decode_control_transfer(
    uc_engine *uc,
    uint64_t addr,
    const uint8_t *insn,
    uint32_t size);