#pragma once

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>
#include <remill/Version/Version.h>

#include <set>

#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG 1

using Memory = std::map<uint64_t, uint8_t>;

struct SimpleTraceManager : remill::TraceManager
{
    const remill::Arch *arch = nullptr;
    llvm::Module *module = nullptr;
    Memory &memory;
    const LIEF::Binary *binary = nullptr;
    uint64_t entry = 0;
    std::unordered_map<uint64_t, llvm::Function *> traces;
    const llvm::Module *defs_module = nullptr;
    std::set<llvm::Function *> undefined_externals;
    std::set<llvm::Function *> defined_externals;

    SimpleTraceManager(const remill::Arch *arch,
                       llvm::Module *module,
                       Memory &memory,
                       const LIEF::Binary *binary,
                       uint64_t entry,
                       const llvm::Module *defs_module);

    // Called when we have lifted, i.e. defined the contents, of a new trace.
    // The derived class is expected to do something useful with this.
    void SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func) override;

    // Get a declaration for a lifted trace. The idea here is that a derived
    // class might have additional global info available to them that lets
    // them declare traces ahead of time. In order to distinguish between
    // stuff we've lifted, and stuff we haven't lifted, we allow the lifter
    // to access "defined" vs. "declared" traces.
    //
    // NOTE: This is permitted to return a function from an arbitrary module.
    llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override;

    // Try to read an executable byte of memory. Returns `true` of the byte
    // at address `addr` is executable and readable, and updates the byte
    // pointed to by `byte` with the read value.
    bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override;

    // Get a definition for a lifted trace.
    //
    // NOTE: This is permitted to return a function from an arbitrary module.
    llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override;

    std::string TraceName(uint64_t addr) override;

private:
    bool isExecutableSection(const uint64_t addr) const;
};