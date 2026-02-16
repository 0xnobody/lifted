#pragma once

#include "verifier_state.hpp"

#include <memory>
#include <vector>

namespace LIEF
{
    class Binary;
}

namespace lifted::verification
{

    /// Generate test states with sequential seeds.
    std::vector<std::unique_ptr<verifier_state>> generate_test_states(
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_rva,
        size_t count,
        uint64_t seed_base);

    /// Template for generating custom verifier_state subclasses.
    template <typename StateT = verifier_state>
    std::vector<std::unique_ptr<StateT>> generate_custom_test_states(
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_rva,
        size_t count,
        uint64_t seed_base)
    {
        static_assert(std::is_base_of<verifier_state, StateT>::value,
                      "StateT must derive from verifier_state");

        std::vector<std::unique_ptr<StateT>> states;
        states.reserve(count);

        for (size_t i = 0; i < count; ++i)
        {
            states.push_back(std::make_unique<StateT>(
                seed_base + i, binary, entry_rva));
        }

        return states;
    }

} // namespace lifted::verification
