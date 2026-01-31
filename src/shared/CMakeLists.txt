project(lifted-shared)

add_library(lifted-shared INTERFACE
    "memory_state.hpp"
    "paged_memory_state.hpp"
)

target_include_directories(lifted-shared INTERFACE "include")