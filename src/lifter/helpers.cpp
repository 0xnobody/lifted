
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

    llvm::Error link_symbolic_helpers(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_SYMBOLIC_PATH);
    }

    llvm::Error link_abi_helpers(llvm::Module *module)
    {
        return utils::link_from_file(module, HELPERS_ABI_PATH);
    }

    // Modules `src` and `dst` already have verification intrinsics linked in.
    // `src` -> function is called __src_fn
    // `dst` -> function is called __tgt_fn
    llvm::Expected<std::unique_ptr<llvm::Module>> link_verification_harness(std::unique_ptr<llvm::Module> src, std::unique_ptr<llvm::Module> dst)
    {
        auto harness_module = utils::load_module_from_file(HELPERS_VERIFICATION_HARNESS_PATH, src->getContext());
        if (!harness_module)
        {
            return harness_module.takeError();
        }

        // Link harness with src and dst
        //
        if (llvm::Linker::linkModules(**harness_module, std::move(src)))
        {
            return llvm::make_error<llvm::StringError>(
                "Error linking verification harness to src module",
                llvm::inconvertibleErrorCode());
        }
        if (llvm::Linker::linkModules(**harness_module, std::move(dst)))
        {
            return llvm::make_error<llvm::StringError>(
                "Error linking verification harness to dst module",
                llvm::inconvertibleErrorCode());
        }
        return harness_module;
    }

}