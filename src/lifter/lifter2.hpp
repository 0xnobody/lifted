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
#include "abi/calling_convention.hpp"

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

        Type Type;
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
    };

    /// Metadata about a called function, resolved from the defs module.
    /// Carries enough information to emit typed ABI-conformant call stubs.
    struct Callee
    {
        /// Function name as it appears in the defs module (e.g., "printf").
        /// May be empty for unknown indirect calls (uses default type).
        std::string FuncName;

        /// The LLVM function type for this specific call site.
        /// For variadic functions, each call site can have a different type.
        /// nullptr means "use the calling convention's default type".
        llvm::FunctionType *OrigType = nullptr;

        /// Per-callee calling convention override.
        /// nullptr means "use the Lifter's default CC".
        const abi::CallingConvention *CC = nullptr;

        /// Whether we have enough info for a typed call.
        /// True even without OrigType — we'll fall back to the CC's default.
        bool isTyped() const { return OrigType != nullptr || !FuncName.empty(); }
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
        std::set<llvm::AddressRange> GotTableRvaRanges;

        llvm::Module *Module;
        std::unique_ptr<llvm::Module> CleanModule;

        /// User-provided function declarations for external/indirect calls.
        /// nullptr if no defs module is available (fallback to opaque calls).
        const llvm::Module *DefsModule = nullptr;

        /// Default calling convention used when a Callee doesn't specify one.
        const abi::CallingConvention *DefaultCC = nullptr;

        /// Counter for disambiguating Fn* wrapper names across callsites
        /// with the same function name but different types (e.g., variadic calls).
        unsigned NextWrapperID = 0;

        /// Tracks Fn* wrapper declarations created for external calls.
        /// Maps the wrapper function to its original Callee metadata.
        std::map<llvm::Function *, Callee> ExternalWrappers;

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

        /// Get or create an Fn* wrapper declaration for a typed external call.
        /// Signature: RetTy funcname_extern_N(UserParams..., i64 %addr, ptr %memory_ptr)
        /// Each callsite gets a unique wrapper (N is disambiguated) to support
        /// variadic functions with different signatures at different sites.
        llvm::Function *GetOrCreateExternWrapper(llvm::Module *M, const Callee &callee);

        /// Resolve the calling convention for a specific callee.
        /// Falls back to DefaultCC if the callee doesn't specify one.
        const abi::CallingConvention *ResolveCC(const Callee &callee) const
        {
            return callee.CC ? callee.CC : DefaultCC;
        }

        /// Resolve the function type for a callee.
        /// Uses OrigType if set, otherwise falls back to the CC's default type.
        llvm::FunctionType *ResolveCalleeType(const Callee &callee) const;

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

        void runCFGPipeline(llvm::Function &F);

        ResolvedTargetsResult HeuresticallyResolveIndirectTargets(llvm::Function &F);
        ResolvedTargetsResult HeuresticallyResolveTargets(llvm::Function &F);

    public:
        Lifter(const remill::Arch *arch,
               const LIEF::Binary *binary,
               llvm::Module *module,
               const std::set<llvm::AddressRange> &const_rva_ranges,
               const std::set<llvm::AddressRange> &got_table_rva_ranges,
               const llvm::Module *defs_module = nullptr,
               const abi::CallingConvention *cc = nullptr)
            : Arch{arch},
              Intrinsics{arch->GetInstrinsicTable()},
              Binary{binary},
              Module{module},
              CleanModule{std::make_unique<llvm::Module>("clean_module", module->getContext())},
              ConstMemoryRvaRanges{const_rva_ranges},
              GotTableRvaRanges{got_table_rva_ranges},
              DefsModule{defs_module},
              DefaultCC{cc}
        {
        }

        LiftedBB LiftBB(uintptr_t id, std::optional<uintptr_t> stop_at = std::nullopt);
        LiftedBB CreateRemoteCallSyntheticBB(bb_id_t id, std::optional<Callee> callee_info = std::nullopt);

        ResolvedTargetsResult ResolveTargets(const LiftedBB &BB);

        void Lift(uint64_t entry_point);
    };
}