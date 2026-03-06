// Internal shared helpers for DOT generation.
// Included by cfg_dot.cpp and pipeline_overlay.cpp only — not part of the public API.
#pragma once

#include "lifter/lifter_types.hpp"
#include "verification/verifier_state.hpp"

#include <remill/Arch/Instruction.h>

#include <algorithm>
#include <cstdio>
#include <string>

namespace lifted::visualization::detail {

// ── Node ID ──────────────────────────────────────────────────────────────────

/// DOT node identifier (unquoted) for a basic block.
inline std::string bb_node_id(lifter::bb_id_t id)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "bb_%016llx",
                  static_cast<unsigned long long>(id));
    return buf;
}

// ── DOT label escaping ────────────────────────────────────────────────────────

/// Escape a string for use inside a DOT record label field.
/// Escapes: \ " | { } < >
inline std::string safe_dot(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '|':  out += "\\|";  break;
        case '{':  out += "\\{";  break;
        case '}':  out += "\\}";  break;
        case '<':  out += "\\<";  break;
        case '>':  out += "\\>";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

// ── Instruction category abbreviation ────────────────────────────────────────

/// Short human-readable abbreviation for a Remill instruction category.
inline const char *term_abbrev(remill::Instruction::Category c)
{
    using C = remill::Instruction::Category;
    switch (c) {
    case C::kCategoryInvalid:                         return "INV";
    case C::kCategoryNormal:                          return "NORM";
    case C::kCategoryNoOp:                            return "NOP";
    case C::kCategoryError:                           return "ERR";
    case C::kCategoryDirectJump:                      return "JMP";
    case C::kCategoryIndirectJump:                    return "IJMP";
    case C::kCategoryConditionalBranch:               return "CBR";
    case C::kCategoryConditionalIndirectJump:         return "CIJMP";
    case C::kCategoryDirectFunctionCall:              return "CALL";
    case C::kCategoryConditionalDirectFunctionCall:   return "CCALL";
    case C::kCategoryIndirectFunctionCall:            return "ICALL";
    case C::kCategoryConditionalIndirectFunctionCall: return "CICALL";
    case C::kCategoryFunctionReturn:                  return "RET";
    case C::kCategoryConditionalFunctionReturn:       return "CRET";
    case C::kCategoryAsyncHyperCall:                  return "HVC";
    case C::kCategoryConditionalAsyncHyperCall:       return "CHVC";
    default:                                          return "?";
    }
}

// ── Block label helpers ───────────────────────────────────────────────────────

/// Address range string "0x<start>..0x<end>" for a REAL block.
inline std::string real_block_range(const lifter::lifted_bb_t &bb)
{
    if (!bb.rva_range)
        return "";
    char buf[48];
    std::snprintf(buf, sizeof(buf), "0x%llx..0x%llx",
                  static_cast<unsigned long long>(bb.rva_range->start()),
                  static_cast<unsigned long long>(bb.rva_range->end()));
    return buf;
}

// ── Heat-map color ────────────────────────────────────────────────────────────

/// Map an execution hit count to an HTML hex colour string.
///
/// Colour palette (warm, eye-friendly, all readable with black text):
///   unhit         → #e8e8e8  (light gray — clearly distinct from "cold" blocks)
///   ratio = 0.00  → #fff8dc  (cornsilk, very pale warm white)
///   ratio = 0.33  → #ffd700  (gold)
///   ratio = 0.66  → #ff8c42  (deep saffron / light orange)
///   ratio = 1.00  → #c75000  (burnt orange — warm and readable, no harsh red)
///
/// hits == 0 always returns the unhit grey regardless of max_hits.
inline std::string heat_color(uint64_t hits, uint64_t max_hits)
{
    if (hits == 0)
        return "#e8e8e8";

    const double ratio = (max_hits == 0)
                             ? 0.0
                             : std::clamp(
                                   static_cast<double>(hits) /
                                       static_cast<double>(max_hits),
                                   0.0, 1.0);

    struct RGB { int r, g, b; };
    static constexpr RGB stops[4] = {
        {0xff, 0xf8, 0xdc}, // cornsilk
        {0xff, 0xd7, 0x00}, // gold
        {0xff, 0x8c, 0x42}, // deep saffron
        {0xc7, 0x50, 0x00}, // burnt orange
    };

    const double seg = ratio * 3.0;
    const int    s   = std::min(static_cast<int>(seg), 2);
    const double t   = seg - static_cast<double>(s);

    auto lerp = [](int a, int b, double lt) {
        return static_cast<int>(static_cast<double>(a) +
                                static_cast<double>(b - a) * lt + 0.5);
    };

    const int r = lerp(stops[s].r, stops[s + 1].r, t);
    const int g = lerp(stops[s].g, stops[s + 1].g, t);
    const int b = lerp(stops[s].b, stops[s + 1].b, t);

    char buf[8];
    std::snprintf(buf, sizeof(buf), "#%02x%02x%02x", r, g, b);
    return buf;
}

// ── exit_type string ─────────────────────────────────────────────────────────

inline const char *exit_type_str(verification::exit_type et)
{
    using E = verification::exit_type;
    switch (et) {
    case E::NATURAL_EXIT:            return "NATURAL_EXIT";
    case E::EXCEPTION:               return "EXCEPTION";
    case E::MISSING_BLOCK:           return "MISSING_BLOCK";
    case E::CHECKPOINT_MISMATCH:     return "CHECKPOINT_MISMATCH";
    case E::LAST_CHECKPOINT_REACHED: return "LAST_CHECKPOINT_REACHED";
    case E::LOOP_LIMIT:              return "LOOP_LIMIT";
    case E::BB_LIMIT:                return "BB_LIMIT";
    default:                         return "UNKNOWN";
    }
}

} // namespace lifted::visualization::detail
