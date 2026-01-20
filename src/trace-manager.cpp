
#include "trace-manager.hpp"

SimpleTraceManager::SimpleTraceManager(const remill::Arch *arch,
                                       llvm::Module *module,
                                       Memory &memory,
                                       const LIEF::Binary *binary,
                                       uint64_t entry,
                                       const llvm::Module *defs_module)
    : arch(arch), module(module), memory(memory), binary(binary), entry(entry), defs_module(defs_module)
{
}

void SimpleTraceManager::SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func)
{
    traces[addr] = lifted_func;
}

llvm::Function *SimpleTraceManager::GetLiftedTraceDeclaration(uint64_t addr)
{
    // Bit of a hack
    // TODO: move RedefineExternalCallsPass into lifter implemenataion
    //
    llvm::Twine name = "sub_" + llvm::Twine::utohexstr(addr);
    auto fn = module->getFunction(name.str());
    if (fn)
    {
        return fn;
    }

    return remill::TraceManager::GetLiftedTraceDeclaration(addr);
}

bool SimpleTraceManager::TryReadExecutableByte(uint64_t addr, uint8_t *byte)
{
    if (binary != nullptr)
    {
        if (!isExecutableSection(addr))
        {
            return false;
        }
        auto content = binary->get_content_from_virtual_address(addr, 1);
        if (content.empty())
        {
            std::cerr << "Warning: reached end of section?" << std::endl;
            return false;
        }
        if (byte != nullptr)
        {
            *byte = content[0];
        }
        return true;
    }
    else
    {
        auto byte_it = memory.find(addr);
        if (byte_it != memory.end())
        {
            if (byte != nullptr)
            {
                *byte = byte_it->second;
            }
            return true;
        }
        else
        {
            return false;
        }
    }
}

llvm::Function *SimpleTraceManager::GetLiftedTraceDefinition(uint64_t addr)
{
    // The entry function needs to be lifted by the TraceLifter
    if (addr == entry)
    {
        return nullptr;
    }

    // The get_trace_decl in TraceLifter creates a declaration for us.
    // Instead of providing an implementation, we keep it extern.
    auto name = TraceName(addr);
    auto fn = module->getFunction(name);
    if (fn == nullptr)
    {
        fn = arch->DeclareLiftedFunction(name, module);
    }

    if (!defs_module)
    {
        undefined_externals.insert(fn);
    }
    else if (auto fn_def = defs_module->getFunction(name); fn_def == nullptr)
    {
        undefined_externals.insert(fn);
    }
    else
    {
        defined_externals.insert(fn_def);
    }

    return fn;
}

std::string SimpleTraceManager::TraceName(uint64_t addr)
{
    for (auto &symbol : binary->symbols())
    {
        auto name = symbol.name();
        auto val = symbol.value();
        if (val == addr && !name.empty())
        {
            return name;
        }
    }
    return remill::TraceManager::TraceName(addr);
}

bool SimpleTraceManager::isExecutableSection(const uint64_t addr) const
{
    auto format = binary->format();
    switch (format)
    {
    case LIEF::EXE_FORMATS::FORMAT_ELF:
    {
        auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(binary);
        auto *section = elf->section_from_virtual_address(addr);
        if (!section)
            return false;
        return section->has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
    }
    break;
    case LIEF::EXE_FORMATS::FORMAT_PE:
    {
        uint64_t address = addr - binary->imagebase();
        auto *pe = dynamic_cast<const LIEF::PE::Binary *>(binary);
        auto *section = pe->section_from_rva(address);
        if (!section)
            return false;
        return section->has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
    }
    break;
    case LIEF::EXE_FORMATS::FORMAT_MACHO:
    {
        auto *macho = dynamic_cast<const LIEF::MachO::Binary *>(binary);
        auto *section = macho->section_from_virtual_address(addr);
        if (!section)
            return false;
        return section->has(LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS);
    }
    break;
    default:
    {
        throw std::runtime_error("Unsupported LIEF format");
    }
    break;
    }
    return false;
}