#pragma once

#include <string>

#include <llvm/Support/Error.h>
#include <llvm/ADT/AddressRanges.h>

namespace LIEF
{
    class Binary;
}

namespace lifted::eval
{

    llvm::Expected<uint64_t> rva_from_export(const LIEF::Binary &binary, const std::string &export_name);
    std::optional<llvm::AddressRange> get_section_bounds(const LIEF::Binary &binary, std::string name);
}