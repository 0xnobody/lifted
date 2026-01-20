#pragma once

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <llvm/Support/Error.h>

#include <remill/Arch/Arch.h>

#include "trace-manager.hpp"

#include <memory>

#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG 1

namespace lifted::lifter
{
    struct LiftingResult
    {
        std::unique_ptr<llvm::Module> module;
        llvm::Function *lifted_function;

        std::set<llvm::Function *> externals_for_redefinition;
    };

    llvm::Expected<uint32_t> rva_from_export(const LIEF::Binary &binary, const std::string &export_name);

    llvm::Expected<LiftingResult> lift_function(const remill::Arch &arch, const LIEF::Binary &binary, uint64_t rva, const llvm::Module *defs = nullptr);
}
