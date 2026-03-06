#include "cfg_dot.hpp"
#include "dot_helpers.hpp"

#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace lifted::visualization {

using namespace detail;

namespace {

// ── Edge style emission ────────────────────────────────────────────────────────

void emit_edge_style(std::ostringstream &os,
                     lifter::edge_t::Type t,
                     bool show_labels)
{
    using T = lifter::edge_t::Type;
    switch (t) {
    case T::CONTROL_FLOW:
        // Default style — no extra attributes needed.
        break;
    case T::FALLTHROUGH:
        os << " [style=dashed, color=gray";
        if (show_labels) os << ", label=\"fall\"";
        os << "]";
        break;
    case T::SYNTHETIC_EXTERNAL:
        os << " [style=dotted, color=steelblue";
        if (show_labels) os << ", label=\"ext\"";
        os << "]";
        break;
    case T::SYNTHETIC_INDIRECT:
        os << " [style=dotted, color=salmon";
        if (show_labels) os << ", label=\"ind\"";
        os << "]";
        break;
    case T::SYNTHETIC_RETURN:
        os << " [style=dashed, color=darkgreen";
        if (show_labels) os << ", label=\"ret\"";
        os << "]";
        break;
    }
}

} // anonymous namespace

// ── cfg_to_dot ──────────────────────────────────────────────────────────────

std::string cfg_to_dot(const CfgSnapshot &cfg, const CfgDotOptions &opts)
{
    using ET  = lifter::edge_t::Type;
    using BBT = lifter::lifted_bb_t::Type;

    // ── Merge-synthetic pre-processing ─────────────────────────────────────
    // synth_to_caller: synthetic block id → real caller block id
    // caller_annotations: caller id → list of callee annotation strings
    // merged_edges: {caller_id, continuation_id, label_str}
    std::map<lifter::bb_id_t, lifter::bb_id_t> synth_to_caller;
    std::map<lifter::bb_id_t, std::vector<std::string>> caller_annotations;
    std::vector<std::tuple<lifter::bb_id_t, lifter::bb_id_t, std::string>> merged_edges;

    if (opts.merge_synthetic) {
        // Pass 1: populate synth_to_caller from SYNTHETIC_EXTERNAL/INDIRECT edges.
        for (const auto &e : cfg.edges) {
            if (e.type == ET::SYNTHETIC_EXTERNAL || e.type == ET::SYNTHETIC_INDIRECT) {
                synth_to_caller[e.dest] = e.source;
                std::string ann;
                auto si_it = cfg.synthetic_blocks.find(e.dest);
                if (si_it != cfg.synthetic_blocks.end()) {
                    const auto &si = si_it->second;
                    if (si.callee_info && !si.callee_info->func_name.empty())
                        ann = "\xe2\x86\x92 " + si.callee_info->func_name + "()";
                    else if (si.type == lifter::synthetic_block_info_t::Type::INDIRECT)
                        ann = "\xe2\x86\x92 indirect()";
                    else
                        ann = "\xe2\x86\x92 ext_call()";
                } else {
                    ann = "\xe2\x86\x92 call()";
                }
                caller_annotations[e.source].push_back(ann);
            }
        }
        // Pass 2: build merged_edges from SYNTHETIC_RETURN edges.
        for (const auto &e : cfg.edges) {
            if (e.type == ET::SYNTHETIC_RETURN) {
                auto caller_it = synth_to_caller.find(e.source);
                if (caller_it == synth_to_caller.end())
                    continue;
                lifter::bb_id_t caller = caller_it->second;
                std::string label;
                auto si_it = cfg.synthetic_blocks.find(e.source);
                if (si_it != cfg.synthetic_blocks.end() &&
                    si_it->second.callee_info &&
                    !si_it->second.callee_info->func_name.empty())
                    label = si_it->second.callee_info->func_name;
                else
                    label = "call/ret";
                merged_edges.emplace_back(caller, e.dest, label);
            }
        }
    }

    std::ostringstream os;

    // ── Graph header ─────────────────────────────────────────────────────────
    os << "digraph CFG {\n";
    os << "    graph [rankdir=" << opts.rankdir
       << ", fontname=\"Courier New\", nodesep=0.5, ranksep=0.8";
    if (!opts.graph_title.empty())
        os << ", label=\"" << safe_dot(opts.graph_title) << "\", labelloc=t";
    os << "];\n";
    os << "    node  [shape=Mrecord, fontname=\"Courier New\", fontsize=10, "
          "style=filled, fillcolor=white];\n";
    os << "    edge  [fontname=\"Courier New\", fontsize=8];\n\n";

    // ── Basic blocks ─────────────────────────────────────────────────────────
    for (const auto &bb : cfg.basic_blocks) {
        bool is_synth = (bb.type == BBT::SYNTHETIC);
        if (opts.merge_synthetic && is_synth)
            continue; // folded into caller

        os << "    \"" << bb_node_id(bb.id) << "\" [label=\"";

        if (!is_synth) {
            bool first = true;
            auto sep   = [&]() { if (!first) os << " | "; first = false; };


            if (opts.show_rva_range && bb.rva_range) {
                sep(); os << real_block_range(bb);
            }
            if (opts.show_term_cat && bb.terminating_category) {
                sep(); os << term_abbrev(*bb.terminating_category);
            }
            if (bb.was_truncated_by_stop) {
                sep(); os << "TRUNC";
            }
            // Merged call annotations.
            if (opts.merge_synthetic) {
                auto ann_it = caller_annotations.find(bb.id);
                if (ann_it != caller_annotations.end()) {
                    for (const auto &a : ann_it->second) {
                        sep(); os << safe_dot(a);
                    }
                }
            }
        } else {
            // Synthetic block (full mode).
            auto it = cfg.synthetic_blocks.find(bb.id);
            if (it != cfg.synthetic_blocks.end()) {
                const auto &si = it->second;
                switch (si.type) {
                case lifter::synthetic_block_info_t::Type::EXTERNAL:
                    if (si.callee_info && !si.callee_info->func_name.empty())
                        os << safe_dot(si.callee_info->func_name);
                    else
                        os << "ext_call";
                    break;
                case lifter::synthetic_block_info_t::Type::INDIRECT:
                    os << "indirect";
                    break;
                }
            } else {
                os << "synthetic";
            }
        }

        os << "\"";

        // Entry block: double border.
        if (!is_synth && bb.rva_range && bb.rva_range->start() == cfg.entry_rva)
            os << ", penwidth=2";

        // Synthetic nodes: distinct shape + fill.
        if (is_synth) {
            auto it = cfg.synthetic_blocks.find(bb.id);
            if (it != cfg.synthetic_blocks.end() &&
                it->second.type == lifter::synthetic_block_info_t::Type::EXTERNAL)
                os << ", shape=hexagon, fillcolor=lightblue, style=filled";
            else
                os << ", shape=hexagon, fillcolor=lightsalmon, style=filled";
        }

        os << "];\n";
    }

    os << "\n";

    // ── Edges ─────────────────────────────────────────────────────────────────
    for (const auto &e : cfg.edges) {
        bool is_synth_edge = (e.type == ET::SYNTHETIC_EXTERNAL ||
                               e.type == ET::SYNTHETIC_INDIRECT ||
                               e.type == ET::SYNTHETIC_RETURN);
        if (opts.merge_synthetic && is_synth_edge)
            continue;

        os << "    \"" << bb_node_id(e.source) << "\" -> \"" << bb_node_id(e.dest) << "\"";
        emit_edge_style(os, e.type, opts.show_edge_labels);
        os << ";\n";
    }

    // Merged call-return edges.
    if (opts.merge_synthetic) {
        for (const auto &[caller, cont, label] : merged_edges) {
            os << "    \"" << bb_node_id(caller) << "\" -> \"" << bb_node_id(cont) << "\""
               << " [style=dashed, color=darkgreen";
            if (opts.show_edge_labels)
                os << ", label=\"" << safe_dot(label) << "\"";
            os << "];\n";
        }
    }

    os << "}\n";
    return os.str();
}

} // namespace lifted::visualization
