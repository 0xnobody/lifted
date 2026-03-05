project("lifted-tests")

add_executable(lifted-tests
    "test_main.cpp"
    "test_sentinel_oracle.cpp"
    "test_paged_memory.cpp"
    "test_checkpoint.cpp"
    "test_comparator.cpp"
    "test_comparator_diff.cpp"
    "test_value_generator.cpp"
    "test_lifter_multi_function.cpp"
)
target_link_libraries(lifted-tests PRIVATE lifted)

# Provide the binary path for the multi-function lift test.
if(DEFINED EVAL_TWO_FUNCS_SO)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_TWO_FUNCS_SO="${EVAL_TWO_FUNCS_SO}"
    )
    add_dependencies(lifted-tests eval-two-funcs)
endif()

target_link_libraries(lifted-tests PRIVATE lifted)
