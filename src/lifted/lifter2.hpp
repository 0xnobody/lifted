#pragma once

#include <llvm/ADT/AddressRanges.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <stack>
#include <set>
#include <map>
#include <cstdint>

// #include <lifted/shared.hpp>

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

    struct Edge
    {
        bb_id_t Source;
        bb_id_t Dest;
        enum class Type
        {
            CONTROL_FLOW,       // Normal jumps/branches discovered via ResolveTargets
            FALLTHROUGH,        // Sequential flow created during block splitting
            SYNTHETIC_EXTERNAL, // Edge from a real block to an external call dispatcher
            SYNTHETIC_INDIRECT, // Edge from a real block to an indirect call dispatcher
            SYNTHETIC_RETURN    // Edge from a synthetic dispatcher back to its continuation (return address block)
        } Type;

        // Default to CONTROL_FLOW for backward compatibility
        Edge(bb_id_t src, bb_id_t dst, enum Type type = Type::CONTROL_FLOW)
            : Source(src), Dest(dst), Type(type) {}

        bool operator<(const Edge &other) const
        {
            return std::tie(Source, Dest, Type) < std::tie(other.Source, other.Dest, other.Type);
        }

        bool operator==(const Edge &other) const
        {
            return Source == other.Source && Dest == other.Dest && Type == other.Type;
        }
    };

    struct LiftResult
    {
        std::unique_ptr<llvm::Module> Module;
        llvm::Function *LiftedFunction;
        std::set<Edge> Edges;
        std::set<LiftedBB> BasicBlocks;
    };

    class Lifter
    {
    private:
        const remill::Arch *Arch;
        const remill::IntrinsicTable *Intrinsics;
        const LIEF::Binary *Binary;

        std::set<llvm::AddressRange> ConstMemoryRvaRanges;
        std::set<llvm::AddressRange> GotTableRvaRanges;
        std::set<llvm::AddressRange> ExtFuncRvaRanges;

        llvm::Module *Module;
        std::unique_ptr<llvm::Module> CleanModule;

        /// User-provided function declarations for external/indirect calls.
        /// nullptr if no defs module is available (fallback to opaque calls).
        const llvm::Module *DefsModule = nullptr;

        /// Default calling convention used when a Callee doesn't specify one.
        const abi::CallingConvention *DefaultCC = nullptr;

        /// Tracks per-callee stub functions created for external calls.
        /// Maps the callee name to its stub function and original Callee metadata.
        /// Each distinct callee (by name) gets one __lifted_<abi>_call_<name> stub.
        struct CalleeStubEntry
        {
            std::string StubFuncName;
            std::string ExtCallDeclName; // The __lifted_ext_call_<name> declaration
            Callee Info;
        };
        std::map<std::string, CalleeStubEntry> CalleeStubs; // <name> (of) __lifted_ext_call_<name> -> CalleeStubEntry
        unsigned NextIndirectStubID = 0;

        bb_id_t NextSyntheticID = 0xFFFF'0000'0000'0000; // Start of synthetic ID range

        std::deque<bb_id_t> Worklist;
        std::map<bb_id_t, LiftedBB> Explored;
        std::set<bb_id_t> Reprove;
        std::set<Edge> Edges;
        std::map<bb_id_t, SyntheticBlockInfo> SyntheticBlocks;

        /// Index for deduplicating EXTERNAL synthetic edges on reprove.
        /// Maps (source_bb_id, dest_addr) -> existing synthetic block ID.
        /// Prevents minting a new synthetic block when the same callsite is
        /// re-resolved after a predecessor is added.
        std::map<std::pair<bb_id_t, uint64_t>, bb_id_t> ExternalSyntheticIndex;

        /// Index for deduplicating INDIRECT synthetic edges on reprove.
        /// Maps source_bb_id -> existing synthetic block ID.
        /// A BB can have at most one indirect outgoing edge.
        std::map<bb_id_t, bb_id_t> IndirectSyntheticIndex;

        // Check if any edge exists between src and dst (ignoring type)
        bool hasEdgeBetween(bb_id_t src, bb_id_t dst) const
        {
            return std::any_of(Edges.begin(), Edges.end(),
                               [&](const Edge &e)
                               { return e.Source == src && e.Dest == dst; });
        }

        /// Insert `root` and all blocks transitively reachable from it (via Edges)
        /// into the Reprove set. Used whenever a new predecessor edge is added to
        /// an already-explored block, so its backward-slice changes and its
        /// resolved targets must be re-checked.
        void reproveSubtree(bb_id_t root);

        /// Find the nearest already-explored REAL block whose start address is
        /// strictly greater than `curr_id`. Returns nullopt if none exists.
        /// Used to clamp LiftBB so it doesn't overrun an already-explored block.
        std::optional<bb_id_t> findNextExploredRealBB(bb_id_t curr_id) const;

        bool IsExecutableSection(const uint64_t addr) const;
        bool TryReadExecutableByte(uint64_t addr, uint8_t *byte);
        std::string ReadInstructionBytes(uint64_t addr);

        llvm::Function *ConcretizeEntryPC(llvm::Function *F, unsigned pc_param_idx, uint64_t concrete_pc);

        static void OptimizeLiftedBB(llvm::Function *BBFunc);

        llvm::Function *stitchCFG(
            llvm::Module *Module,
            const std::set<bb_id_t> &BlockSet,
            llvm::StringRef NewFuncName,
            uintptr_t TargetAddr,                  // 0 if no specific target to intercept
            bool DeadEndIsUnreachable,             // true for slicing, false for full CFG
            bool InstrumentBasicBlockEntry = false // true to call __lifted_bb_entered at start of each REAL block
        );

        /// Create a concrete wrapper for a position-independent CFG function.
        /// Takes a 4-parameter CFG function (state, rva, memory, base) and returns
        /// a 3-parameter wrapper (state, rva, memory) that calls it with a concrete base.
        llvm::Function *concretizeCFGBase(
            llvm::Function *BasedFunc,
            uint64_t ConcreteBase,
            llvm::StringRef ConcreteName = "");

        /// Build a CFG function covering all blocks that can REACH TargetID (backward slice).
        /// Execution is intercepted at TargetID so callers can inspect the resulting PC.
        /// Used by ResolveTargets to determine successor addresses of a single basic block.
        llvm::Function *buildBackwardSliceCFG(llvm::Module *Module, bb_id_t TargetID, llvm::StringRef Name,
                                              bool InstrumentBasicBlockEntry = false);

        /// Build a CFG function covering all blocks REACHABLE FROM RootID (forward slice).
        /// Produces the full lifted function graph from an entry point.
        /// Used by Lift() to construct the final lifted function.
        llvm::Function *buildForwardCFG(llvm::Module *Module, bb_id_t RootID, llvm::StringRef Name,
                                        bool InstrumentBasicBlockEntry = false,
                                        std::set<Edge> *OutEdges = nullptr, std::set<LiftedBB> *OutBlocks = nullptr);

        /// Get or create a per-callee ABI stub that saves non-volatile registers,
        /// calls an opaque __lifted_ext_call_<name>, restores non-volatile registers,
        /// and pops the return address. Returns the stub function.
        llvm::Function *GetOrCreateCalleeStub(llvm::Module *M, const Callee &callee);

        /// Resolve the calling convention for a specific callee.
        /// Falls back to DefaultCC if the callee doesn't specify one.
        const abi::CallingConvention *ResolveCC(std::optional<Callee> callee) const
        {
            return callee && callee->CC ? callee->CC : DefaultCC;
        }

        /// Resolve the function type for a callee.
        /// Uses OrigType if set, otherwise falls back to the CC's default type.
        llvm::FunctionType *ResolveCalleeType(const Callee &callee) const;

        void dumpLifterState()
        {
            llvm::outs() << "Worklist: [";
            for (const auto &id : Worklist)
            {
                llvm::outs() << "\n\t0x" << llvm::format_hex(id, 16) << ",";
            }
            llvm::outs() << "]\n";

            llvm::outs() << "Reprove: [";
            for (const auto &id : Reprove)
            {
                llvm::outs() << "\n\t0x" << llvm::format_hex(id, 16) << ",";
            }
            llvm::outs() << "]\n";

            llvm::outs() << "Explored: [";
            for (const auto &pair : Explored)
            {
                const auto &bb = pair.second;
                llvm::outs() << "\n\t{ID: 0x" << llvm::format_hex(bb.ID, 16)
                             << ", FuncName: " << bb.FuncName
                             << ", RVARange: " << (bb.RVARange ? ("[0x" + llvm::utohexstr(bb.RVARange->start()) + ", 0x" + llvm::utohexstr(bb.RVARange->end()) + ")") : "nullopt")
                             << ", TerminatingCategory: " << (bb.TerminatingCategory ? std::to_string(static_cast<int>(*bb.TerminatingCategory)) : "nullopt")
                             << "},";
            }
            llvm::outs() << "]\n";

            // Use decltype to avoid the Edge::Type member/enum-class name collision.
            using EdgeTypeEnum = std::decay_t<decltype(std::declval<Edge>().Type)>;
            auto EdgeTypeName = [](EdgeTypeEnum t) -> llvm::StringRef
            {
                switch (t)
                {
                case EdgeTypeEnum::CONTROL_FLOW:
                    return "CONTROL_FLOW";
                case EdgeTypeEnum::FALLTHROUGH:
                    return "FALLTHROUGH";
                case EdgeTypeEnum::SYNTHETIC_EXTERNAL:
                    return "SYNTHETIC_EXTERNAL";
                case EdgeTypeEnum::SYNTHETIC_INDIRECT:
                    return "SYNTHETIC_INDIRECT";
                case EdgeTypeEnum::SYNTHETIC_RETURN:
                    return "SYNTHETIC_RETURN";
                default:
                    return "UNKNOWN";
                }
            };
            llvm::outs() << "Edges: [";
            for (const auto &edge : Edges)
            {
                llvm::outs() << "\n\t(0x" << llvm::format_hex(edge.Source, 16)
                             << " -> 0x" << llvm::format_hex(edge.Dest, 16) << " [" << EdgeTypeName(edge.Type) << "]),";
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
               const std::set<llvm::AddressRange> &ext_func_rva_ranges,
               const llvm::Module *defs_module = nullptr,
               const abi::CallingConvention *cc = nullptr)
            : Arch{arch},
              Intrinsics{arch->GetInstrinsicTable()},
              Binary{binary},
              Module{module},
              CleanModule{std::make_unique<llvm::Module>("clean_module", module->getContext())},
              ConstMemoryRvaRanges{const_rva_ranges},
              GotTableRvaRanges{got_table_rva_ranges},
              ExtFuncRvaRanges{ext_func_rva_ranges},
              DefsModule{defs_module},
              DefaultCC{cc}
        {
        }

        LiftedBB LiftBB(uintptr_t id, std::optional<uintptr_t> stop_at = std::nullopt);
        LiftedBB CreateRemoteCallSyntheticBB(bb_id_t id, std::optional<Callee> callee_info = std::nullopt);

        ResolvedTargetsResult ResolveTargets(const LiftedBB &BB, uint64_t entry_rva);

        llvm::Expected<LiftResult> Lift(uint64_t entry_rva, bool InstrumentBasicBlockEntry = false);
    };
}