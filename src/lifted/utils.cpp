
#include "utils.hpp"

#include <llvm/AsmParser/Parser.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/raw_ostream.h>

#include <remill/Arch/X86/Runtime/State.h>

#include "third-party/nmd_assembly.h"

#include "compat/lief_compat.hpp"

namespace lifted::utils
{

std::error_code output_to_file(std::filesystem::path path, llvm::Module *module)
{
    std::filesystem::create_directories(path.parent_path());

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

    // Link the helpers module with the main module.
    // Normalize the helper module's data layout and triple to match the
    // destination so llvm::Linker doesn't emit spurious mismatch warnings.
    // The layouts are functionally compatible — helpers never use the
    // address spaces (p270/p271/p272) that differ between the two.
    helpers_module->setDataLayout(module->getDataLayout());
    helpers_module->setTargetTriple(module->getTargetTriple());

    if (llvm::Linker::linkModules(*module, std::move(helpers_module)))
    {
        return llvm::make_error<llvm::StringError>(
            "Failed to link helpers module with main module",
            llvm::inconvertibleErrorCode());
    }

    return llvm::Error::success();
}

llvm::Expected<std::unique_ptr<llvm::Module>> load_module_from_file(std::filesystem::path path, llvm::LLVMContext &ctx)
{
    // Try to open the file into a MemoryBuffer
    auto bufferOrErr = llvm::MemoryBuffer::getFile(path.string());
    if (!bufferOrErr)
    {
        return llvm::errorCodeToError(bufferOrErr.getError());
    }

    auto &buffer = *bufferOrErr;

    // Try to parse bitcode first
    auto bitcodeOrErr = llvm::parseBitcodeFile(buffer->getMemBufferRef(), ctx);
    if (bitcodeOrErr)
    {
        return std::move(*bitcodeOrErr);
    }

    // If bitcode parsing failed, try textual IR (.ll)
    llvm::SMDiagnostic err;
    auto module = llvm::parseAssemblyFile(path.string(), err, ctx);
    if (!module)
    {
        return llvm::make_error<llvm::StringError>(
            "Failed to parse module from file: " + path.string(),
            llvm::inconvertibleErrorCode());
    }

    return module;
}

std::string insn_bytes_to_str(std::span<const uint8_t> bytes, uintptr_t addr)
{
    nmd_x86_instruction instruction;
    std::string formatted;
    formatted.resize(128);

    // Decode and format
    if (nmd_x86_decode(bytes.data(), bytes.size(), &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_NONE))
    {
        // UNSAFE
        nmd_x86_format(&instruction, formatted.data(), addr, NMD_X86_FORMAT_FLAGS_DEFAULT);
    }
    else
    {
        formatted = "<invalid instruction>";
    }

    if (addr)
    {
        return llvm::formatv("{0:x16}: {1}", addr, formatted).str();
    }

    return formatted;
}

void print_state(const State &state, std::ostream &os)
{
    llvm::raw_os_ostream llvm_os(os);
    llvm_os << "RIP: " << llvm::format_hex(state.gpr.rip.qword, 16) << "\n";
    llvm_os << "RSP: " << llvm::format_hex(state.gpr.rsp.qword, 16) << "\n";
    llvm_os << "RBP: " << llvm::format_hex(state.gpr.rbp.qword, 16) << "\n";
    llvm_os << "RAX: " << llvm::format_hex(state.gpr.rax.qword, 16) << "\n";
    llvm_os << "RBX: " << llvm::format_hex(state.gpr.rbx.qword, 16) << "\n";
    llvm_os << "RCX: " << llvm::format_hex(state.gpr.rcx.qword, 16) << "\n";
    llvm_os << "RDX: " << llvm::format_hex(state.gpr.rdx.qword, 16) << "\n";
    llvm_os << "RSI: " << llvm::format_hex(state.gpr.rsi.qword, 16) << "\n";
    llvm_os << "RDI: " << llvm::format_hex(state.gpr.rdi.qword, 16) << "\n";
    llvm_os << "R8 : " << llvm::format_hex(state.gpr.r8.qword, 16) << "\n";
    llvm_os << "R9 : " << llvm::format_hex(state.gpr.r9.qword, 16) << "\n";
    llvm_os << "R10: " << llvm::format_hex(state.gpr.r10.qword, 16) << "\n";
    llvm_os << "R11: " << llvm::format_hex(state.gpr.r11.qword, 16) << "\n";
    llvm_os << "R12: " << llvm::format_hex(state.gpr.r12.qword, 16) << "\n";
    llvm_os << "R13: " << llvm::format_hex(state.gpr.r13.qword, 16) << "\n";
    llvm_os << "R14: " << llvm::format_hex(state.gpr.r14.qword, 16) << "\n";
    llvm_os << "R15: " << llvm::format_hex(state.gpr.r15.qword, 16) << "\n";
}

llvm::Expected<uint64_t> rva_from_export(const LIEF::Binary &binary, const std::string &export_name)
{
    auto exports = binary.exported_functions();
    for (const auto &exp : exports)
    {
        if (exp.name() == export_name)
        {
            return exp.address() - binary.imagebase();
        }
    }
    return llvm::createStringError(llvm::inconvertibleErrorCode(), "Export not found: " + export_name);
}

std::optional<llvm::AddressRange> get_section_bounds(const LIEF::Binary &binary, std::string name)
{
    auto format = binary.format();
    switch (format)
    {
    case LIEF::EXE_FORMATS::FORMAT_ELF:
    {
        auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(&binary);
        auto *section = elf->get_section(name);
        if (!section)
            return std::nullopt;
        return llvm::AddressRange{section->virtual_address(), section->virtual_address() + section->size()};
    }
    break;
    case LIEF::EXE_FORMATS::FORMAT_PE:
    {
        auto *pe = dynamic_cast<const LIEF::PE::Binary *>(&binary);
        auto *section = pe->get_section(name);
        if (!section)
            return std::nullopt;
        return llvm::AddressRange{section->virtual_address(), section->virtual_address() + section->size()};
    }
    break;
    case LIEF::EXE_FORMATS::FORMAT_MACHO:
    {
        auto *macho = dynamic_cast<const LIEF::MachO::Binary *>(&binary);
        auto *section = macho->get_section(name);
        if (!section)
            return std::nullopt;
        return llvm::AddressRange{section->virtual_address(), section->virtual_address() + section->size()};
    }
    break;
    default:
    {
        throw std::runtime_error("Unsupported LIEF format");
    }
    break;
    }
}
} // namespace lifted::utils