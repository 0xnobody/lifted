#pragma once

#include <cstdint>
#include <memory>

#include <llvm/Support/Error.h>

#include <remill/Arch/X86/Runtime/State.h>

namespace llvm
{
    class Function;
}

namespace LIEF
{
    class Binary;
}

class verifier_state;

namespace lifted
{
    llvm::Expected<verifier_state> run_verifier_test(
        llvm::Function *remill_function,
        uint64_t seed,
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_addr);
}
