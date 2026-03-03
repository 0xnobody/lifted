#include "seed_sweep_stage.hpp"

#include "../../hash_mix.hpp"

#include <cstdio>
#include <string>

namespace lifted::pipeline {

SeedSweepStage::SeedSweepStage(RunConfig base_config, uint64_t count)
    : base_(std::move(base_config)), count_(count)
{
}

std::string SeedSweepStage::name() const
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(base_.seed));
    return "SeedSweep(" + std::to_string(count_) +
           " runs, base_seed=" + buf + ")";
}

std::vector<RunConfig> SeedSweepStage::generate_configs(const Corpus &) const
{
    std::vector<RunConfig> configs;
    configs.reserve(count_);
    for (uint64_t i = 0; i < count_; ++i)
    {
        RunConfig cfg  = base_;
        cfg.seed       = hash::mix(base_.seed, i);
        configs.push_back(std::move(cfg));
    }
    return configs;
}

} // namespace lifted::pipeline
