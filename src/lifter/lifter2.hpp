#pragma once

#include <llvm/ADT/AddressRanges.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <stack>
#include <set>
#include <map>
#include <cstdint>

#include <lifted/shared.hpp>

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
    using bb_id_t = uintptr_t;

    inline bool IsSynthetic(bb_id_t id)
    {
        return (id & 0xFFFF'0000'0000'0000) == 0xFFFF'0000'0000'0000;
    }

    struct LiftedBB
    {
        enum class Type
        {
            REAL,     // A real basic block with a known instruction range
            SYNTHETIC // A synthetic basic block with no associated instruction range (e.g., for handling indirect jumps)
        };

        bb_id_t ID;
        llvm::StringRef FuncName;
        std::optional<llvm::AddressRange> RVARange;                       // Only for real BBs.
        std::optional<remill::Instruction::Category> TerminatingCategory; // Only for real BBs.

        bool operator<(const LiftedBB &other) const
        {
            return ID < other.ID;
        }

        bool operator==(const LiftedBB &other) const
        {
            return ID == other.ID;
        }

        Type getType() const
        {
            return IsSynthetic(ID) ? Type::SYNTHETIC : Type::REAL;
        }
        
        bool isSynthetic() const
        {
            return IsSynthetic(ID);
        }
    };

    class Callee
    {
    };

    struct ResolvedTarget
    {
        enum class Type
        {
            INTERNAL, // Part of the function -- continue lifting
            EXTERNAL, // External function -- issue an ext call
        };

        Type Type;
        uint64_t Dest;                         // Address, not bb_id_t -- returns address for both INTERNAL and EXTERNAL types.
        std::optional<Callee> CalleeInfo = {}; // Only valid for EXTERNAL types
    };

    struct ResolvedTargetsResult
    {
        std::vector<ResolvedTarget> Targets;
        std::optional<Callee> IndirectTarget;

        operator bool() const
        {
            return !Targets.empty() || IndirectTarget.has_value();
        }
    };

    struct SyntheticBlockInfo
    {
        enum class Type
        {
            EXTERNAL,
            INDIRECT
        };

        Type Type;
        std::optional<uint64_t> DestAddr; // Only valid for EXTERNAL types -- the address of the external function being called.
        std::optional<Callee> CalleeInfo; // Valid for both
    };

    inline llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const ResolvedTarget &target)
    {
        switch (target.Type)
        {
        case ResolvedTarget::Type::INTERNAL:
            os << "INTERNAL(0x" << llvm::format_hex(target.Dest, 16) << ")";
            break;
        case ResolvedTarget::Type::EXTERNAL:
            os << "EXTERNAL(0x" << llvm::format_hex(target.Dest, 16) << ")";
            break;
        }
        return os;
    }

    class Lifter
    {
    private:
        const remill::Arch *Arch;
        const remill::IntrinsicTable *Intrinsics;
        const LIEF::Binary *Binary;

        std::set<llvm::AddressRange> ConstMemoryRvaRanges;

        llvm::Module *Module;
        std::unique_ptr<llvm::Module> CleanModule;

        bb_id_t InitialEntryPoint;
        bb_id_t NextSyntheticID = 0xFFFF'0000'0000'0000; // Start of synthetic ID range

        std::deque<bb_id_t> Worklist;
        std::map<bb_id_t, LiftedBB> Explored;
        std::set<bb_id_t> Reprove;
        std::set<std::pair<bb_id_t, bb_id_t>> Edges;
        std::map<bb_id_t, SyntheticBlockInfo> SyntheticBlocks;

        bool IsExecutableSection(const uint64_t addr) const;
        bool TryReadExecutableByte(uint64_t addr, uint8_t *byte);
        std::string ReadInstructionBytes(uint64_t addr);

        llvm::Function *ConcretizeEntryPC(llvm::Function *F, unsigned pc_param_idx, uint64_t concrete_pc);

        static void OptimizeLiftedBB(llvm::Function *BBFunc);

        llvm::Function *stitchCFG(
            llvm::Module *Module,
            const std::set<bb_id_t> &BlockSet,
            llvm::StringRef NewFuncName,
            uintptr_t TargetAddr,     // 0 if no specific target to intercept
            bool DeadEndIsUnreachable // true for slicing, false for full CFG
        );

        llvm::Function *buildPartialCFG(llvm::Module *Module, const LiftedBB &BB);
        llvm::Function *buildCFG(llvm::Module *Module);

        void dumpLifterState()
        {
            llvm::outs() << "Worklist: [";
            for (const auto &id : Worklist)
            {
                llvm::outs() << "0x" << llvm::format_hex(id, 16) << ", ";
            }
            llvm::outs() << "]\n";

            llvm::outs() << "Reprove: [";
            for (const auto &id : Reprove)
            {
                llvm::outs() << "0x" << llvm::format_hex(id, 16) << ", ";
            }
            llvm::outs() << "]\n";

            llvm::outs() << "Explored: [";
            for (const auto &pair : Explored)
            {
                const auto &bb = pair.second;
                llvm::outs() << "{ID: 0x" << llvm::format_hex(bb.ID, 16)
                             << ", FuncName: " << bb.FuncName
                             << ", RVARange: " << (bb.RVARange ? ("[0x" + llvm::utohexstr(bb.RVARange->start()) + ", 0x" + llvm::utohexstr(bb.RVARange->end()) + ")") : "nullopt")
                             << ", TerminatingCategory: " << (bb.TerminatingCategory ? std::to_string(static_cast<int>(*bb.TerminatingCategory)) : "nullopt")
                             << "}, ";
            }
            llvm::outs() << "]\n";

            llvm::outs() << "Edges: [";
            for (const auto &edge : Edges)
            {
                llvm::outs() << "(0x" << llvm::format_hex(edge.first, 16)
                             << " -> 0x" << llvm::format_hex(edge.second, 16) << "), ";
            }
            llvm::outs() << "]\n";
        }

        void issueExtCall(llvm::BasicBlock &BB, bb_id_t id);

        void runCFGPipeline(llvm::Function &F);

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

        LiftedBB LiftBB(uintptr_t id, std::optional<uintptr_t> stop_at = std::nullopt);

        ResolvedTargetsResult ResolveTargets(const LiftedBB &BB);

        void Lift(uint64_t entry_point);
    };
}