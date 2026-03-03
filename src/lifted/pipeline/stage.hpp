#pragma once

#include "run_config.hpp"
#include "corpus.hpp"

#include <string>
#include <vector>

namespace lifted::pipeline {

/// Abstract pipeline stage.  A stage generates a sequence of RunConfigs.
/// The pipeline orchestrator handles execution, comparison, and corpus updates.
///
/// Stages are pure producers: they inspect the accumulated corpus from previous
/// stages (read-only) to decide what configurations to emit, but they do not
/// execute anything themselves.
class PipelineStage
{
public:
    virtual ~PipelineStage() = default;

    virtual std::string name() const = 0;

    /// Generate all RunConfigs for this stage.
    /// input_corpus: corpus accumulated from all previous stages (may be empty).
    virtual std::vector<RunConfig> generate_configs(const Corpus &input_corpus) const = 0;
};

} // namespace lifted::pipeline
