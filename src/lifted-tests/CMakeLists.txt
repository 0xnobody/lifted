project("lifted-tests")

add_executable(lifted-tests
    "test_main.cpp"
    "test_sentinel_oracle.cpp"
    "test_paged_memory.cpp"
    "test_checkpoint.cpp"
    "test_comparator.cpp"
    "test_comparator_diff.cpp"
)

target_link_libraries(lifted-tests PRIVATE lifted)
