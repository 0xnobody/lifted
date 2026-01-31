
#include "utils.hpp"

#include <llvm/IR/Module.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/AsmParser/Parser.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Linker/Linker.h>

namespace lifted::utils
{
    
std::error_code output_to_file(std::filesystem::path path, llvm::Module *module)
{
    std::error_code ec;
    llvm::raw_fd_ostream raw(path.string(), ec, llvm::sys::fs::OF_Text);
    if (ec)
    {
        return ec;
    }

    module->print(raw, nullptr);

    return {};
}

llvm::Error link_from_file(llvm::Module *module, std::filesystem::path helpers_path)
{
    llvm::LLVMContext &context = module->getContext();
    llvm::SMDiagnostic error;
    auto helpers_module = llvm::parseAssemblyFile(helpers_path.string(), error, context);
    if (!helpers_module)
    {
        return llvm::make_error<llvm::StringError>(
            "Failed to load helpers module from file: " + helpers_path.string(),
            llvm::inconvertibleErrorCode());
    }

    // Link the helpers module with the main module
    if (llvm::Linker::linkModules(*module, std::move(helpers_module)))
    {
        return llvm::make_error<llvm::StringError>(
            "Failed to link helpers module with main module",
            llvm::inconvertibleErrorCode());
    }

    return llvm::Error::success();
}

llvm::Expected<std::unique_ptr<llvm::Module>> load_module_from_file(std::filesystem::path path, llvm::LLVMContext &ctx) {
    // Try to open the file into a MemoryBuffer
    auto bufferOrErr = llvm::MemoryBuffer::getFile(path.string());
    if (!bufferOrErr) {
        return llvm::errorCodeToError(bufferOrErr.getError());
    }

    auto &buffer = *bufferOrErr;

    // Try to parse bitcode first
    auto bitcodeOrErr = llvm::parseBitcodeFile(buffer->getMemBufferRef(), ctx);
    if (bitcodeOrErr) {
        return std::move(*bitcodeOrErr);
    }

    // If bitcode parsing failed, try textual IR (.ll)
    llvm::SMDiagnostic err;
    auto module = llvm::parseAssemblyFile(path.string(), err, ctx);
    if (!module) {
        return llvm::make_error<llvm::StringError>(
            "Failed to parse module from file: " + path.string(),
            llvm::inconvertibleErrorCode());
    }

    return module;
}
} // namespace lifted::utils