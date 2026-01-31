project(lifted-verifier)

add_executable(verifier
    "verifier.cpp"
    "verifier.hpp"
    "ext_call_policy.hpp"
    "ext_call_policy.cpp"
    "uc_raii.hpp"
    "uc_raii.cpp"
)

set_target_properties(verifier PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(verifier PRIVATE unicorn_external lifted-shared LIEF::LIEF)

add_dependencies(verifier helpers lifted-shared)