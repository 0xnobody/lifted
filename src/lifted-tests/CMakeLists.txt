project("lifted-tests")

add_executable(lifted-tests
    "test_main.cpp"
    "test_sentinel_oracle.cpp"
    "test_paged_memory.cpp"
    "test_checkpoint.cpp"
    "test_comparator.cpp"
    "test_comparator_diff.cpp"
    "test_value_generator.cpp"
    "test_lift_context.cpp"
    "test_lifter_multi_function.cpp"
    "test_verifier_state_loop_limit.cpp"
    "test_verifier_state_recursive.cpp"
    "test_state_fold.cpp"
    "test_binary_context_annotations.cpp"
 )

target_link_libraries(lifted-tests PRIVATE lifted)

# Provide the binary path for the multi-function lift test.
if(DEFINED EVAL_TWO_FUNCS_SO)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_TWO_FUNCS_SO="${EVAL_TWO_FUNCS_SO}"
    )
    add_dependencies(lifted-tests eval-two-funcs)
endif()

get_property(EVAL_IOFILE_SO GLOBAL PROPERTY "_EVAL_TARGET_IOFILE_SO")
if(EVAL_IOFILE_SO)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_IOFILE_SO="${EVAL_IOFILE_SO}"
    )
    add_dependencies(lifted-tests eval-iofile)
endif()
