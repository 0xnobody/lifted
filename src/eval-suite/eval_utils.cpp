#include "eval_utils.hpp"

#ifdef DEBUG
#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG
#else
#include <LIEF/LIEF.hpp>
#endif

namespace lifted::eval
{
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
}
