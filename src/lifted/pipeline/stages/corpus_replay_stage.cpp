#include "corpus_replay_stage.hpp"

#include "../../hash_mix.hpp"

#include <string>

namespace lifted::pipeline {

CorpusReplayStage::CorpusReplayStage()
    : extra_base_(std::nullopt), extra_count_(0)
{
}

CorpusReplayStage::CorpusReplayStage(RunConfig extra_base, uint64_t extra_count)
    : extra_base_(std::move(extra_base)), extra_count_(extra_count)
{
}

std::string CorpusReplayStage::name() const
{
    if (extra_base_)
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(extra_base_->seed));
        return "CorpusReplay+SeedSweep(" + std::to_string(extra_count_) +
               " extra runs, base_seed=" + buf + ")";
    }
    return "CorpusReplay";
}

std::vector<RunConfig> CorpusReplayStage::generate_configs(const Corpus &input_corpus) const
{
    std::vector<RunConfig> configs;

    // Replay all corpus entries verbatim.
    for (const auto &entry : input_corpus.entries())
        configs.push_back(entry.config);

    // Append extra seed sweep if configured.
    if (extra_base_)
    {
        for (uint64_t i = 0; i < extra_count_; ++i)
        {
            RunConfig cfg = *extra_base_;
            cfg.seed      = hash::mix(extra_base_->seed, i);
            configs.push_back(std::move(cfg));
        }
    }

    return configs;
}

} // namespace lifted::pipeline
