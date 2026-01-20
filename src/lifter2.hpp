#pragma once

#include <llvm/ADT/AddressRanges.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <stack>
#include <set>
#include <map>
#include <cstdint>

#include "utils.hpp"
#include "opt.hpp"
#include "helpers.hpp"

namespace llvm
{
    class Function;
}

namespace LIEF
{
    class Binary;
}

namespace lifted
{
    struct LiftedBB
    {
        llvm::StringRef FuncName;
        llvm::AddressRange RVARange;
        remill::Instruction::Category TerminatingCategory;

        bool operator<(const LiftedBB &other) const
        {
            return RVARange.operator<(other.RVARange);
        }

        bool operator==(const LiftedBB &other) const
        {
            return RVARange == other.RVARange;
        }
    };

    class Lifter
    {
    private:
        const remill::Arch *Arch;
        const remill::IntrinsicTable *Intrinsics;
        const LIEF::Binary *Binary;

        std::set<llvm::AddressRange> ConstMemoryRvaRanges;

        llvm::Module *Module;
        std::unique_ptr<llvm::Module> CleanModule;

        std::deque<uintptr_t> Worklist;
        std::map<uintptr_t, LiftedBB> Explored;
        std::set<uintptr_t> Reprove;
        std::set<std::pair<uintptr_t, uintptr_t>> Edges;

        bool IsExecutableSection(const uint64_t addr) const;
        bool TryReadExecutableByte(uint64_t addr, uint8_t *byte);
        std::string ReadInstructionBytes(uint64_t addr);

        llvm::Function *ConcretizeEntryPC(llvm::Function *F, unsigned pc_param_idx, uint64_t concrete_pc);

        static void OptimizeLiftedBB(llvm::Function *BBFunc);

        llvm::Function *stitchCFG(
            llvm::Module *Module,
            const std::set<uintptr_t> &BlockSet,
            llvm::StringRef NewFuncName,
            uintptr_t TargetAddr,     // 0 if no specific target to intercept
            bool DeadEndIsUnreachable // true for slicing, false for full CFG
        );

        llvm::Function *buildPartialCFG(llvm::Module *Module, const LiftedBB &BB);
        llvm::Function *buildCFG(llvm::Module *Module);

        void dumpLifterState()
        {
            llvm::outs() << "=== Lifter State ===\n";
            llvm::outs() << "Worklist:\n";
            for (uintptr_t addr : Worklist)
            {
                llvm::outs() << "  0x" << llvm::format_hex(addr, 16) << "\n";
            }
            llvm::outs() << "Reprove Set:\n";
            for (const auto &addr : Reprove)
            {
                llvm::outs() << "  0x" << llvm::format_hex(addr, 16) << "\n";
            }
            llvm::outs() << "Explored BBs:\n";
            for (const auto &[addr, bb] : Explored)
            {
                llvm::outs() << "  0x" << llvm::format_hex(addr, 16) << " : " << bb.FuncName << " [" << llvm::format_hex(bb.RVARange.start(), 16) << ", " << llvm::format_hex(bb.RVARange.end(), 16) << "]\n";
            }
            llvm::outs() << "Known Edges:\n";
            for (const auto &[src, dst] : Edges)
            {
                llvm::outs() << "  0x" << llvm::format_hex(src, 16) << " -> 0x" << llvm::format_hex(dst, 16) << "\n";
            }
            llvm::outs() << "====================\n";
        }

    public:
        Lifter(const remill::Arch *arch,
               const LIEF::Binary *binary,
               llvm::Module *module,
               const std::set<llvm::AddressRange> &const_rva_ranges)
            : Arch{arch},
              Intrinsics{arch->GetInstrinsicTable()},
              Binary{binary},
              Module{module},
              CleanModule{std::make_unique<llvm::Module>("clean_module", module->getContext())},
              ConstMemoryRvaRanges{const_rva_ranges}
        {
        }

        LiftedBB LiftBB(uint64_t addr);

        std::set<uintptr_t> ResolveTargets(const LiftedBB &BB);

        void Lift(uint64_t addr);
    };
}