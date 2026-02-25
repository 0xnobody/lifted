
#include "helpers.hpp"

#include "utils.hpp"

#include <llvm/IR/Module.h>

#include <llvm/Linker/Linker.h>

namespace lifted::helpers
{

    llvm::Error link_deobfuscation_intrinsics(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_DEOBFUSCATION_INTRINSICS_PATH);
    }

    llvm::Error link_verification_intrinsics(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_VERIFICATION_INTRINSICS_PATH);
    }

    llvm::Error link_state_utils(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_STATE_UTILS_PATH);
    }

    llvm::Error link_abi_helpers(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_ABI_PATH);
    }

    llvm::Error link_lifting_helpers(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_LIFTING_PATH);
    }
}