project(lifted-shared)

add_library(lifted-shared STATIC
    "logging.hpp"
    "logging.cpp"
    "paged_memory_state.hpp"
    "paged_memory_state.cpp"
    "reg_state.hpp"
)

set_target_properties(lifted-shared PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(lifted-shared PUBLIC "include")

target_link_libraries(lifted-shared PRIVATE remill LIEF::LIEF)