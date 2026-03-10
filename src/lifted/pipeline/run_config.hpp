#pragma once

#include "../verification/verifier_state.hpp"
#include "../verification/sentinel_oracle.hpp"
#include "../verification/value_generator.hpp"
#include "../verification/checkpoint.hpp"
#include "../verification/event_flags.hpp"
#include "../binary_context.hpp"

#include "compat/lief_compat.hpp"

#include <cstdint>
#include <climits>
#include <memory>

namespace lifted::pipeline {

/// Owned, copyable configuration for a single run.
///
/// Stored in the corpus and replayed verbatim against future executor pairs.
/// Generates the transient run_params_t / verification_params_t structs on
/// demand — those structs hold raw pointers into this object, so they MUST NOT
/// outlive the RunConfig that produced them.
struct RunConfig
{
    uint64_t seed = 0;

    /// Sentinel oracle — stored by value so every corpus entry is self-contained
    /// and copyable without shared ownership.
    verification::sentinel_oracle oracle{};

    /// Value generator factory — polymorphic, user-extensible.
    /// Stored as shared_ptr so copies are cheap and the factory can be shared
    /// across many RunConfigs produced by the same stage.
    /// Default: unconstrained uniform random.
    std::shared_ptr<const verification::value_generator_factory> gen_factory =
        std::make_shared<verification::uniform_value_generator_factory>();

    /// Execution limits wired into verification_params_t.
    /// UINT64_MAX means unlimited (the verifier_state defaults).
    uint64_t bb_limit   = UINT64_MAX;
    uint64_t loop_limit = UINT64_MAX;

    /// How self-recursive calls are handled during verification.
    verification::recursive_call_policy recursive_policy =
        verification::recursive_call_policy::SKIP;

    /// Which events to record in checkpoints (passed to checkpoint_config_t::record_on).
    verification::event_flags record_flags = verification::event_flags::DEFAULT;

    /// When true, each checkpointed event also stores a full checkpoint_detail_t
    /// (including the remill::State copy for BB/EXT_CALL events).  Off by default.
    bool record_details = false;

    // ── Conversion helpers ────────────────────────────────────────────────────

    /// Produce the transient executor params for one run invocation.
    /// bin_ctx and entry_rva are target-level — not stored per-run.
    ///
    /// LIFETIME: The returned run_params_t holds &this->oracle and
    /// gen_factory.get().  It MUST NOT outlive this RunConfig instance.
    verification::run_params_t to_run_params(
        const lifted::BinaryContext &bin_ctx,
        uint64_t entry_rva) const
    {
        return {
            .seed              = seed,
            .bin_ctx           = &bin_ctx,
            .entry_rva         = entry_rva,
            .oracle            = &oracle,
            .value_gen_factory = gen_factory.get(),
        };
    }

    /// Produce the verification params for one run invocation.
    /// prev_record is set by the pipeline orchestrator, not stored per config.
    verification::verification_params_t to_verif_params(
        const verification::checkpoint_record_t *prev_record = nullptr) const
    {
        return {
            .checkpoint_config = {
                .record_on      = record_flags,
                .prev_record    = prev_record,
                .record_details = record_details,
            },
            .loop_policy = verification::loop_limit_policy::TERMINATE,
            .bb_limit = bb_limit,
            .loop_limit = loop_limit,
            .recursive_policy = recursive_policy,
        };
    }
};

} // namespace lifted::pipeline
