#pragma once

#include "../stage.hpp"

#include <cstdint>
#include <string>

namespace lifted::pipeline {

/// Generates 'count' RunConfigs from a base config.
/// Seeds are derived as hash::mix(base.seed, i) for i in [0, count).
/// All other fields of the base config are inherited verbatim.
class SeedSweepStage : public PipelineStage
{
public:
    SeedSweepStage(RunConfig base_config, uint64_t count);

    std::string name() const override;

    /// Ignores input_corpus — always produces the same sweep.
    std::vector<RunConfig> generate_configs(const Corpus &input_corpus) const override;

private:
    RunConfig base_;
    uint64_t  count_;
};

} // namespace lifted::pipeline
