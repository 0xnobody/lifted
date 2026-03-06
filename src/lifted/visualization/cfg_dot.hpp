#pragma once

#include "cfg_data.hpp"

#include <string>

namespace lifted::visualization {

/// Options controlling the appearance of the base CFG DOT output.
struct CfgDotOptions {
    bool        merge_synthetic = false;  ///< IDA-style: fold synthetic blocks into caller labels.
    std::string rankdir         = "TB";   ///< Graphviz rankdir: TB or LR.
    bool        show_rva_range  = true;   ///< Include byte-range annotation on real blocks.
    bool        show_term_cat   = true;   ///< Include terminator-category abbreviation.
    bool        show_edge_labels = true;  ///< Label non-CONTROL_FLOW edges.
    std::string graph_title;              ///< Optional title appended to the graph label.
};

/// Render @p cfg as a Graphviz DOT string.
std::string cfg_to_dot(const CfgSnapshot &cfg, const CfgDotOptions &opts = {});

} // namespace lifted::visualization
