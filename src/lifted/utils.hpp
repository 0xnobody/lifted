#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <ostream>

#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/Error.h>
#include <llvm/ADT/AddressRanges.h>

namespace llvm
{
    class Module;
    class LLVMContext;
}

namespace LIEF
{
    class Binary;
    namespace ELF
    {
        class Relocation;
    }
}

struct State;

namespace lifted::utils
{
    std::error_code output_to_file(std::filesystem::path path, llvm::Module *module);

    llvm::Error link_from_file(llvm::Module *module, std::filesystem::path helpers_path);

    llvm::Expected<std::unique_ptr<llvm::Module>> load_module_from_file(std::filesystem::path path, llvm::LLVMContext &ctx);

    std::string insn_bytes_to_str(std::span<const uint8_t> bytes, uintptr_t addr = 0);

    void print_state(const State &state, std::ostream &os);

    llvm::Expected<uint64_t> rva_from_export(const LIEF::Binary &binary, const std::string &export_name);

    std::optional<uint64_t> resolve_elf_relocation_word64(const LIEF::ELF::Relocation &reloc,
                                                         uint64_t                     load_base);

    bool has_elf_relocation_at(const LIEF::Binary &binary, uint64_t slot_rva);
    std::optional<uint64_t> read_elf_relocated_word64(const LIEF::Binary &binary,
                                                      uint64_t            slot_rva,
                                                      uint64_t            load_base);

    std::optional<llvm::AddressRange> get_section_bounds(const LIEF::Binary &binary, std::string name);
}