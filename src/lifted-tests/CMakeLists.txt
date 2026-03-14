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
    "test_indirect_call_divergence.cpp"
    "test_visualization.cpp"
 )

target_link_libraries(lifted-tests PRIVATE lifted eval-suite)

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

get_property(EVAL_INDIRECT_CALL_SO GLOBAL PROPERTY "_EVAL_TARGET_INDIRECT_CALL_SO")
if(EVAL_INDIRECT_CALL_SO)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_INDIRECT_CALL_SO="${EVAL_INDIRECT_CALL_SO}"
    )
    add_dependencies(lifted-tests eval-indirect-call)
endif()

get_property(EVAL_INSERTIONSORT_SO GLOBAL PROPERTY "_EVAL_TARGET_INSERTIONSORT_SO")
if(EVAL_INSERTIONSORT_SO)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_INSERTIONSORT_SO="${EVAL_INSERTIONSORT_SO}"
    )
    add_dependencies(lifted-tests eval-insertionsort)
endif()
