#pragma once

#include <llvm/ADT/AddressRanges.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include <remill/Arch/Instruction.h>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "../binary_context.hpp"

namespace llvm
{
class Function;
class FunctionType;
class Module;
} // namespace llvm

namespace lifted::abi
{
class CallingConvention;
} // namespace lifted::abi

namespace lifted::lifter
{

// ── Basic types ────────────────────────────────────────────────────────────

using bb_id_t = uintptr_t;

/// Returns true when `id` is in the synthetic block ID range.
inline bool is_synthetic(bb_id_t id)
{
    return (id & 0xFFFF'0000'0000'0000) == 0xFFFF'0000'0000'0000;
}

// ── lifted_bb_t ───────────────────────────────────────────────────────────

struct lifted_bb_t
{
    enum class Type
    {
        REAL,      ///< A real basic block with a known instruction range.
        SYNTHETIC, ///< A synthetic basic block (e.g. for indirect/external calls).
    };

    Type type;
    bb_id_t id;
    std::string func_name;
    std::optional<llvm::AddressRange> rva_range;                       ///< Only for REAL blocks.
    std::optional<remill::Instruction::Category> terminating_category; ///< Only for REAL blocks.
    /// True when lift_bb was given a stop_at address that actually fired
    /// (i.e. the block was truncated before its natural terminator).
    bool was_truncated_by_stop = false;

    bool operator<(const lifted_bb_t &o) const { return id < o.id; }
    bool operator==(const lifted_bb_t &o) const { return id == o.id; }
};

// ── resolved_target_t ─────────────────────────────────────────────────────

struct resolved_target_t
{
    enum class Type
    {
        INTERNAL,         ///< Part of the function – continue lifting.
        RECURSIVE,        ///< Direct self-recursive call – model via recursive synthetic block.
        EXTERNAL,         ///< External function – emit an ext call stub with a resolved callee annotation.
        RETURN_TO_CALLER, ///< Block exits by returning to its caller (e.g. a `ret`
                          ///  instruction). No dest address; stitched CFG defaults to the
                          ///  natural function return when no continuation is known.
    };
    Type type;
    uint64_t dest;                                ///< Address (RVA for INTERNAL/RECURSIVE, VA for EXTERNAL).
    std::optional<annotation_id_t> annotation_id; ///< Required when type == EXTERNAL.
};

// ── resolved_targets_result_t ─────────────────────────────────────────────

struct resolved_targets_result_t
{
    std::vector<resolved_target_t> targets;

    /// Exists when an indirect call dispatcher target was discovered for this BB.
    std::optional<annotation_id_t> indirect_annotation_id;

    explicit operator bool() const
    {
        return !targets.empty() || indirect_annotation_id;
    }
};

// ── synthetic_block_info_t ────────────────────────────────────────────────

struct synthetic_block_info_t
{
    enum class Type
    {
        EXTERNAL,  ///< External function call dispatcher.
        RECURSIVE, ///< Self-recursive call dispatcher.
        INDIRECT,  ///< Indirect call dispatcher.
    };

    Type type;
    std::optional<uint64_t> dest_addr; ///< Valid for EXTERNAL/RECURSIVE – address used as the dispatch key.
    annotation_id_t annotation_id;     ///< Required for every synthetic call dispatcher.
};

// ── edge_t ────────────────────────────────────────────────────────────────

struct edge_t
{
    bb_id_t source;
    bb_id_t dest;

    enum class Type
    {
        CONTROL_FLOW,             ///< Normal jumps/branches from resolve_targets.
        FALLTHROUGH,              ///< Sequential flow created during block splitting.
        SYNTHETIC_EXTERNAL,       ///< Real block → external call dispatcher.
        SYNTHETIC_RECURSIVE_CALL, ///< Real block → recursive call dispatcher.
        SYNTHETIC_INDIRECT,       ///< Real block → indirect call dispatcher.
        SYNTHETIC_RETURN,         ///< Synthetic dispatcher → continuation (return addr block).
    } type;

    edge_t(bb_id_t src, bb_id_t dst, Type t = Type::CONTROL_FLOW)
        : source(src), dest(dst), type(t)
    {
    }

    bool operator<(const edge_t &o) const
    {
        return std::tie(source, dest, type) < std::tie(o.source, o.dest, o.type);
    }
    bool operator==(const edge_t &o) const
    {
        return source == o.source && dest == o.dest && type == o.type;
    }
};

// ── callee_stub_entry_t ───────────────────────────────────────────────────

struct callee_stub_entry_t
{
    std::string stub_func_name;
    std::string ext_call_decl_name; ///< Empty for recursive stubs that call the shared helper directly.
    annotation_id_t annotation_id;  ///< Non-owning; valid for BinaryContext lifetime.
};

// ── lift_config_t ─────────────────────────────────────────────────────────

struct lift_config_t
{
    bool instrument_bb_entry = false;
};

// ── lift_stats_t ──────────────────────────────────────────────────────────

struct lift_stats_t
{
    size_t bbs_lifted = 0;      ///< BBs lifted from scratch this call.
    size_t bbs_cached = 0;      ///< BBs reused from explore_ cache.
    size_t bbs_total = 0;       ///< Total BBs in the final function.
    double lift_time_ms = 0;    ///< Time in lift_bb + process_bb.
    double resolve_time_ms = 0; ///< Time in resolve_targets.
    double stitch_time_ms = 0;  ///< Time in build_forward_cfg.
    double total_time_ms = 0;   ///< Wall clock for the entire lift() call.

    void print(std::ostream &os) const
    {
        os << "[LIFT STATS]"
           << "\n  lifted=" << bbs_lifted
           << "\n  cached=" << bbs_cached
           << "\n  total=" << bbs_total
           << "\n  lift=" << lift_time_ms << "ms"
           << "\n  resolve=" << resolve_time_ms << "ms"
           << "\n  stitch=" << stitch_time_ms << "ms"
           << "\n  total=" << total_time_ms << "ms";
    }
};

// ── lift_result_t ─────────────────────────────────────────────────────────

struct lift_result_t
{
    std::unique_ptr<llvm::Module> module;
    llvm::Function *lifted_function = nullptr;
    std::set<edge_t> edges;
    std::set<lifted_bb_t> basic_blocks;
    std::map<bb_id_t, synthetic_block_info_t> synthetic_blocks;
    lift_stats_t stats;
};

// ── operator<< ───────────────────────────────────────────────────────────

inline llvm::raw_fd_ostream &operator<<(llvm::raw_fd_ostream &os, const resolved_target_t &t)
{
    switch (t.type)
    {
    case resolved_target_t::Type::INTERNAL:
        os << "INTERNAL(0x" << llvm::format_hex(t.dest, 16) << ")";
        break;
    case resolved_target_t::Type::RECURSIVE:
        os << "RECURSIVE(entry)";
        break;
    case resolved_target_t::Type::EXTERNAL:
        os << "EXTERNAL(0x" << llvm::format_hex(t.dest, 16) << ")";
        break;
    case resolved_target_t::Type::RETURN_TO_CALLER:
        os << "RETURN_TO_CALLER";
        break;
    }
    return os;
}

} // namespace lifted::lifter
