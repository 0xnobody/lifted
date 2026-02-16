#include "test_generator.hpp"

namespace lifted::verification
{

    std::vector<std::unique_ptr<verifier_state>> generate_test_states(
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_rva,
        size_t count,
        uint64_t seed_base)
    {
        std::vector<std::unique_ptr<verifier_state>> states;
        states.reserve(count);

        for (size_t i = 0; i < count; ++i)
        {
            states.push_back(std::make_unique<verifier_state>(
                seed_base + i, binary, entry_rva));
        }

        return states;
    }

} // namespace lifted::verification
