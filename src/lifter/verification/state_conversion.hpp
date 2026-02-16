#pragma once

#include <llvm/Support/Error.h>

#include <remill/Arch/X86/Runtime/State.h>
#include <unicorn/unicorn.h>

#include <cstdint>

namespace lifted::verification
{

    /// Convert Remill State to Unicorn register state.
    llvm::Error state_to_unicorn(const State &state, uc_engine *uc);

    /// Convert Unicorn register state to Remill State.
    State unicorn_to_state(uc_engine *uc);

    /// Setup stack region in Unicorn emulator.
    /// Maps stack, writes return address, sets RSP in init_state.
    llvm::Error setup_unicorn_stack(uc_engine *uc, State &init_state, uint64_t stack_magic, uint64_t finish_magic);

} // namespace lifted::verification
