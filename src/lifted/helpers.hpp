#pragma once

#include <filesystem>
#include <memory>

#include <llvm/Support/Error.h>

namespace llvm
{
    class Module;
}

namespace lifted::helpers
{

    llvm::Error link_deobfuscation_intrinsics(llvm::Module *module);

    llvm::Error link_verification_intrinsics(llvm::Module *module);

    llvm::Error link_state_utils(llvm::Module *module);

    llvm::Error link_lifting_helpers(llvm::Module *module);

    llvm::Error link_abi_helpers(llvm::Module *module);
}