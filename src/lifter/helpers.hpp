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

    llvm::Error link_symbolic_helpers(llvm::Module *module);

    llvm::Error link_lifting_helpers(llvm::Module *module);

    llvm::Error link_abi_helpers(llvm::Module *module);

    // Modules `src` and `dst` already have verification intrinsics linked in.
    // `src` -> function is called __src_fn
    // `dst` -> function is called __tgt_fn
    llvm::Expected<std::unique_ptr<llvm::Module>> link_verification_harness(std::unique_ptr<llvm::Module> src, std::unique_ptr<llvm::Module> dst);

}