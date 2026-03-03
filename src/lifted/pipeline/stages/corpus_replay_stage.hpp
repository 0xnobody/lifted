#pragma once

#include "../stage.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace lifted::pipeline {

/// Replays all RunConfigs from the accumulated input corpus verbatim.
/// Optionally appends a fresh SeedSweep (hash::mix(extra_base.seed, i)) after
/// the replayed entries.
///
/// Typical usage:
///   Stage 1: SeedSweepStage(base, 50)
///   Stage 2: CorpusReplayStage()                 -- replay interesting entries
///   Stage 3: CorpusReplayStage(mutated_base, 20) -- replay + additional sweep
class CorpusReplayStage : public PipelineStage
{
public:
    /// Replay-only constructor.
    CorpusReplayStage();

    /// Replay-plus-sweep constructor: after replaying corpus entries, appends
    /// 'extra_count' configs with seeds derived from extra_base.
    CorpusReplayStage(RunConfig extra_base, uint64_t extra_count);

    std::string name() const override;

    std::vector<RunConfig> generate_configs(const Corpus &input_corpus) const override;

private:
    std::optional<RunConfig> extra_base_;
    uint64_t                 extra_count_ = 0;
};

} // namespace lifted::pipeline
