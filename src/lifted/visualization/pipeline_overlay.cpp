#include "pipeline_overlay.hpp"
#include "dot_helpers.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lifted::visualization {

using namespace detail;

// ── overlay_to_dot ────────────────────────────────────────────────────────────

std::string overlay_to_dot(const CfgSnapshot    &cfg,
                            const OverlayData    &data,
                            const OverlayOptions &opts)
{
    using ET  = lifter::edge_t::Type;
    using BBT = lifter::lifted_bb_t::Type;
    using ETP = verification::exit_type;

    // ── Build RVA → bb_id_t lookup for REAL blocks ──────────────────────────
    std::unordered_map<uint64_t, lifter::bb_id_t> rva_to_id;
    for (const auto &bb : cfg.basic_blocks)
        if (bb.type == BBT::REAL && bb.rva_range)
            rva_to_id[bb.rva_range->start()] = bb.id;

    // ── Compute max_hits for heat-map normalisation ──────────────────────────
    uint64_t max_hits = 0;
    if (data.block_hits)
        for (const auto &[rva, cnt] : *data.block_hits)
            if (cnt > max_hits) max_hits = cnt;

    // ── Resolve divergence information ────────────────────────────────────────
    //
    // divergence_idx : 0-based index into src bb_trace where traces first diverge
    // divergence_rva : RVA of the block at that index (0 if unknown)
    static constexpr size_t kNoIdx = SIZE_MAX;

    size_t   divergence_idx = kNoIdx;
    uint64_t divergence_rva = 0;

    const auto *div = data.divergence;

    if (div) {
        if (div->diff && div->diff->bb_trace_diff) {
            const auto &bdt = *div->diff->bb_trace_diff;
            if (!bdt.entries.empty()) {
                divergence_idx = bdt.entries[0].index;
                if (bdt.entries[0].rva_r1)
                    divergence_rva = *bdt.entries[0].rva_r1;
            }
        }
        if (divergence_idx == kNoIdx && div->comparison.first_trace_divergence) {
            divergence_idx = *div->comparison.first_trace_divergence;
            const auto &trace = div->src_result.bb_trace;
            if (divergence_idx < trace.size())
                divergence_rva = trace[divergence_idx];
        }
    }

    // ── Find divergence block ID ──────────────────────────────────────────────
    lifter::bb_id_t divergence_block_id  = 0;
    bool            has_divergence_block = false;
    if (divergence_rva != 0) {
        auto it = rva_to_id.find(divergence_rva);
        if (it != rva_to_id.end()) {
            divergence_block_id  = it->second;
            has_divergence_block = true;
        }
    }

    // ── Build trace edge set ──────────────────────────────────────────────────
    // Pairs of (source_id, dest_id) along the src bb_trace up to divergence_idx.
    //
    // Executors do NOT record fallthrough edges as distinct trace events.
    // After building the set from consecutive trace pairs, we additionally
    // include any FALLTHROUGH edge whose both endpoints appear in the visited
    // block set — this ensures fallthrough-connected blocks on the path are
    // highlighted correctly even though they were not recorded consecutively.
    std::set<std::pair<lifter::bb_id_t, lifter::bb_id_t>> trace_edge_set;
    std::unordered_set<lifter::bb_id_t>                   visited_ids;

    if (div && opts.show_trace_path && divergence_idx != kNoIdx) {
        const auto  &trace = div->src_result.bb_trace;
        const size_t limit =
            (trace.size() > 0)
                ? std::min(divergence_idx + 1, trace.size())
                : 0;

        // Collect visited block IDs and consecutive pairs.
        for (size_t i = 0; i < limit; ++i) {
            auto it = rva_to_id.find(trace[i]);
            if (it != rva_to_id.end()) {
                visited_ids.insert(it->second);
                if (i + 1 < limit) {
                    auto it2 = rva_to_id.find(trace[i + 1]);
                    if (it2 != rva_to_id.end())
                        trace_edge_set.insert({it->second, it2->second});
                }
            }
        }

        // Include FALLTHROUGH edges between visited blocks (not in executor trace).
        for (const auto &e : cfg.edges) {
            if (e.type == ET::FALLTHROUGH &&
                visited_ids.count(e.source) &&
                visited_ids.count(e.dest))
                trace_edge_set.insert({e.source, e.dest});
        }
    }

    // ── Back-edge detection ───────────────────────────────────────────────────
    // Detect directed back-edges (to a block seen earlier in the trace)
    // and count how many times each was crossed.
    std::map<std::pair<uint64_t, uint64_t>, uint64_t> back_edge_rva_counts;

    if (div && opts.show_loop_counts) {
        const auto &trace = div->src_result.bb_trace;
        std::unordered_map<uint64_t, size_t> first_seen_at;
        for (size_t i = 0; i < trace.size(); ++i)
            first_seen_at.emplace(trace[i], i);
        for (size_t i = 0; i + 1 < trace.size(); ++i) {
            uint64_t from = trace[i];
            uint64_t to   = trace[i + 1];
            auto     it   = first_seen_at.find(to);
            if (it != first_seen_at.end() && it->second < i)
                back_edge_rva_counts[{from, to}]++;
        }
    }

    // ── Escape detection ─────────────────────────────────────────────────────
    bool        need_missing_node    = false;
    uint64_t    escape_block_rva     = 0;
    std::string escape_label;
    std::string escape_border_color;

    if (div && opts.show_escapes) {
        const auto &trace  = div->src_result.bb_trace;
        const auto  reason = div->src_result.exit_reason;

        if (reason == ETP::MISSING_BLOCK && !trace.empty()) {
            escape_block_rva    = trace.back();
            escape_label        = "ESCAPED";
            escape_border_color = "orange";
            need_missing_node   = true;
        } else if (reason == ETP::LOOP_LIMIT && !trace.empty()) {
            escape_block_rva    = trace.back();
            escape_label        = "LOOP_LIMIT";
            escape_border_color = "goldenrod";
        } else if (reason == ETP::BB_LIMIT && !trace.empty()) {
            escape_block_rva    = trace.back();
            escape_label        = "BB_LIMIT";
            escape_border_color = "goldenrod";
        }
    }

    // ── Emit DOT ──────────────────────────────────────────────────────────────
    std::ostringstream os;

    os << "digraph CFG {\n";
    os << "    graph [rankdir=TB, fontname=\"Courier New\", "
          "nodesep=0.5, ranksep=0.8];\n";
    os << "    node  [shape=Mrecord, fontname=\"Courier New\", "
          "fontsize=10, style=filled, fillcolor=white];\n";
    os << "    edge  [fontname=\"Courier New\", fontsize=8];\n\n";

    // ── Nodes ─────────────────────────────────────────────────────────────────
    for (const auto &bb : cfg.basic_blocks) {
        const bool is_synth = (bb.type == BBT::SYNTHETIC);

        std::string fill_color    = "white";  // overwritten per type below
        std::string border_color;
        std::string extra_label;
        double      pen_width     = 1.0;

        // Heat-map fill (REAL blocks only).
        if (!is_synth && bb.rva_range) {
            uint64_t hits = 0;
            if (data.block_hits) {
                auto it = data.block_hits->find(bb.rva_range->start());
                if (it != data.block_hits->end())
                    hits = it->second;
            }
            fill_color = heat_color(hits, max_hits);

            if (opts.show_hit_counts) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "hits: %llu",
                              static_cast<unsigned long long>(hits));
                extra_label += " | ";
                extra_label += buf;
            }
        }

        // Synthetic fill (matches cfg_dot.cpp: lightblue = EXTERNAL, lightsalmon = INDIRECT).
        if (is_synth) {
            auto sit = cfg.synthetic_blocks.find(bb.id);
            if (sit != cfg.synthetic_blocks.end() &&
                sit->second.type == lifter::synthetic_block_info_t::Type::EXTERNAL)
                fill_color = "lightblue";
            else
                fill_color = "lightsalmon";
        }

        // Divergence highlight.
        if (opts.show_divergence && has_divergence_block &&
            bb.id == divergence_block_id) {
            border_color = "red";
            pen_width    = 3.0;
            extra_label += " | DIVERGED";
        }

        // Escape highlight (overrides divergence border for last block).
        if (escape_block_rva != 0 && !is_synth && bb.rva_range &&
            bb.rva_range->start() == escape_block_rva) {
            border_color = escape_border_color;
            pen_width    = 2.0;
            extra_label += " | ";
            extra_label += escape_label;
        }

        // ── Build label ───────────────────────────────────────────────────────
        os << "    \"" << bb_node_id(bb.id) << "\" [label=\"";

        if (!is_synth) {
            bool first = true;
            auto sep   = [&]() { if (!first) os << " | "; first = false; };


            if (opts.cfg_opts.show_rva_range && bb.rva_range) {
                sep(); os << real_block_range(bb);
            }
            if (opts.cfg_opts.show_term_cat && bb.terminating_category) {
                sep(); os << term_abbrev(*bb.terminating_category);
            }
            if (bb.was_truncated_by_stop) {
                sep(); os << "TRUNC";
            }
            os << extra_label;
        } else {
            // Synthetic block label.
            auto it = cfg.synthetic_blocks.find(bb.id);
            if (it != cfg.synthetic_blocks.end()) {
                const auto &si = it->second;
                if (si.type == lifter::synthetic_block_info_t::Type::EXTERNAL) {
                    if (si.callee_info && !si.callee_info->func_name.empty())
                        os << safe_dot(si.callee_info->func_name);
                    else
                        os << "ext_call";
                } else {
                    os << "indirect";
                }
            } else {
                os << "synthetic";
            }
            os << extra_label;
        }

        os << "\"";

        // Style attributes.
        os << ", style=filled";
        os << ", fillcolor=\"" << fill_color << "\"";

        if (!border_color.empty())
            os << ", color=" << border_color;
        if (pen_width != 1.0) {
            char pbuf[16];
            std::snprintf(pbuf, sizeof(pbuf), "%.0f", pen_width);
            os << ", penwidth=" << pbuf;
        }

        // Entry block: double border (when not already overridden).
        if (!is_synth && bb.rva_range &&
            bb.rva_range->start() == cfg.entry_rva &&
            border_color.empty()) {
            os << ", penwidth=2";
        }

        // Synthetic: distinct shape.
        if (is_synth)
            os << ", shape=hexagon";

        os << "];\n";
    }

    os << "\n";

    // ── Edges ─────────────────────────────────────────────────────────────────
    // Build back-edge counts keyed by block ID pair.
    std::map<std::pair<lifter::bb_id_t, lifter::bb_id_t>, uint64_t> back_edge_id_counts;
    for (const auto &[rva_pair, cnt] : back_edge_rva_counts) {
        auto it1 = rva_to_id.find(rva_pair.first);
        auto it2 = rva_to_id.find(rva_pair.second);
        if (it1 != rva_to_id.end() && it2 != rva_to_id.end())
            back_edge_id_counts[{it1->second, it2->second}] += cnt;
    }

    for (const auto &e : cfg.edges) {
        const auto node_pair = std::make_pair(e.source, e.dest);
        const bool is_trace  = trace_edge_set.count(node_pair) > 0;
        const auto back_it   = back_edge_id_counts.find(node_pair);
        const bool is_back   = (back_it != back_edge_id_counts.end());

        os << "    \"" << bb_node_id(e.source)
           << "\" -> \"" << bb_node_id(e.dest) << "\"";

        std::string color;
        std::string style;
        double      pw     = 1.0;
        std::string label;

        // Base style from edge type.
        if (opts.cfg_opts.show_edge_labels) {
            switch (e.type) {
            case ET::FALLTHROUGH:        label = "fall"; break;
            case ET::SYNTHETIC_EXTERNAL: label = "ext";  break;
            case ET::SYNTHETIC_INDIRECT: label = "ind";  break;
            case ET::SYNTHETIC_RETURN:   label = "ret";  break;
            default:                                      break;
            }
        }
        switch (e.type) {
        case ET::FALLTHROUGH:
            style = "dashed";
            color = "gray";
            break;
        case ET::SYNTHETIC_EXTERNAL:
            style = "dotted";
            color = "steelblue";
            break;
        case ET::SYNTHETIC_INDIRECT:
            style = "dotted";
            color = "salmon";
            break;
        case ET::SYNTHETIC_RETURN:
            style = "dashed";
            color = "darkgreen";
            break;
        default:
            break;
        }

        // Overlay: back-edge annotation (wins over trace-path colour).
        if (is_back) {
            color = "purple";
            style = "bold";
            char buf[32];
            std::snprintf(buf, sizeof(buf), "\xc3\x97%llu",
                          static_cast<unsigned long long>(back_it->second));
            if (!label.empty()) label += ' ';
            label += buf;
            pw = is_trace ? 2.0 : 1.0;
        } else if (is_trace) {
            color = "blue";
            pw    = 2.0;
        }

        const bool any = !color.empty() || !style.empty() || pw != 1.0 || !label.empty();
        if (any) {
            os << " [";
            bool first = true;
            auto comma = [&]() { if (!first) os << ", "; first = false; };

            if (!color.empty()) { comma(); os << "color="    << color; }
            if (!style.empty()) { comma(); os << "style="    << style; }
            if (pw != 1.0) {
                char pb[16];
                std::snprintf(pb, sizeof(pb), "%.0f", pw);
                comma(); os << "penwidth=" << pb;
            }
            if (!label.empty()) {
                comma(); os << "label=\"" << safe_dot(label) << "\"";
            }
            os << "]";
        }

        os << ";\n";
    }

    os << "\n";

    // ── Special nodes ─────────────────────────────────────────────────────────

    if (need_missing_node) {
        os << "    \"???\" [shape=doubleoctagon, fillcolor=\"#cc2200\", "
              "fontcolor=white, style=filled, "
              "label=\"??? (missing block)\"];\n";
        auto it = rva_to_id.find(escape_block_rva);
        if (it != rva_to_id.end())
            os << "    \"" << bb_node_id(it->second)
               << "\" -> \"???\" [style=dashed, color=\"#cc2200\"];\n";
        os << "\n";
    }

    // Exit-type badge.
    if (div) {
        os << "    __exit_badge [shape=plaintext, label=\"Exit: "
           << exit_type_str(div->src_result.exit_reason)
           << "\"];\n";
    }

    os << "}\n";
    return os.str();
}

} // namespace lifted::visualization
