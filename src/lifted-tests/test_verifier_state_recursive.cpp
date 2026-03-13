// test_verifier_state_recursive.cpp
//
// Unit tests for verifier_state's recursive-call trace behavior.
// Recursive summaries are skipped during execution but must still appear in the
// shared opaque-call trace so comparator ext-call diffs can compare them.

#include "test_framework.hpp"
#include "verification/verifier_state.hpp"
#include "verification/value_generator.hpp"
#include "verification/event_flags.hpp"

#include <cstdint>
#include <limits>

using namespace lifted::verification;

namespace
{
    static uniform_value_generator_factory s_factory{};

    class RecursiveTraceHarness : public verifier_state
    {
        static run_params_t make_params()
        {
            return {
                .seed = 0,
                .bin_ctx = nullptr,
                .entry_rva = 0x100,
                .oracle = nullptr,
                .value_gen_factory = &s_factory,
            };
        }

        static verification_params_t make_vparams()
        {
            verification_params_t vp;
            vp.checkpoint_config.sync_on = event_flags::NONE; // callbacks receive nullptr State*
            vp.bb_limit = std::numeric_limits<uint64_t>::max();
            vp.loop_limit = std::numeric_limits<uint64_t>::max();
            vp.recursive_policy = recursive_call_policy::SKIP;
            return vp;
        }

    public:
        RecursiveTraceHarness()
            : verifier_state(make_params(), make_vparams())
        {
        }

        bool call_ext(uint64_t addr)
        {
            return context_ptr()->ext_call(context_ptr()->context, nullptr, addr);
        }

        bool call_recursive(uint64_t addr)
        {
            return context_ptr()->recursive_call(context_ptr()->context, nullptr, addr);
        }
    };
}

TEST(verifier_state_recursive_calls_append_to_ext_trace)
{
    RecursiveTraceHarness h;

    CHECK(h.call_ext(0x4000));
    CHECK(h.call_recursive(0x5000));
    CHECK(h.call_ext(0x6000));

    const auto &trace = h.external_calls();
    CHECK_EQ(trace.size(), static_cast<size_t>(3));
    CHECK_EQ(trace[0], static_cast<uint64_t>(0x4000));
    CHECK_EQ(trace[1], static_cast<uint64_t>(0x5000));
    CHECK_EQ(trace[2], static_cast<uint64_t>(0x6000));
}
