#pragma once

#include <filesystem>
#include <memory>
#include <optional>

#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/Error.h>

namespace llvm
{
    class Module;
    class LLVMContext;
}

namespace lifted::utils
{
    
std::error_code output_to_file(std::filesystem::path path, llvm::Module *module);

llvm::Error link_from_file(llvm::Module *module, std::filesystem::path helpers_path);

llvm::Expected<std::unique_ptr<llvm::Module>> load_module_from_file(std::filesystem::path path, llvm::LLVMContext &ctx);

}