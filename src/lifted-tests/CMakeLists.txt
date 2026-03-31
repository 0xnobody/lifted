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
    "test_indirect_call_divergence.cpp"
    "test_elf_relocations.cpp"
    "test_visualization.cpp"
    "test_opaque_call_stub.cpp"
 )

target_link_libraries(lifted-tests PRIVATE lifted eval-suite)

add_executable(lifted-tests-opaque-call-stub
    "test_main.cpp"
    "test_opaque_call_stub.cpp"
)

target_link_libraries(lifted-tests-opaque-call-stub PRIVATE lifted)

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

get_property(EVAL_EXT_CALL_SO GLOBAL PROPERTY "_EVAL_TARGET_EXT_CALL_SO")
if(EVAL_EXT_CALL_SO)
    target_compile_definitions(
        lifted-tests
        PRIVATE
            EVAL_EXT_CALL_SO="${EVAL_EXT_CALL_SO}"
    )
    target_compile_definitions(
        lifted-tests-opaque-call-stub
        PRIVATE
            EVAL_EXT_CALL_SO="${EVAL_EXT_CALL_SO}"
    )
    add_dependencies(lifted-tests eval-ext-call)
    add_dependencies(lifted-tests-opaque-call-stub eval-ext-call)
endif()

get_property(EVAL_INSERTIONSORT_SO GLOBAL PROPERTY "_EVAL_TARGET_INSERTIONSORT_SO")
if(EVAL_INSERTIONSORT_SO)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_INSERTIONSORT_SO="${EVAL_INSERTIONSORT_SO}"
    )
    add_dependencies(lifted-tests eval-insertionsort)
endif()

if(LIFTED_ENABLE_POLARIS AND POLARIS_CLANG_PATH AND EXISTS "${POLARIS_CLANG_PATH}" AND TARGET eval-suite-synthetic)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_ARITHMETIC_POLARIS_SO="${CMAKE_BINARY_DIR}/src/evaluation/synthetic/libeval-arithmetic-polaris.so"
    )
    add_dependencies(lifted-tests eval-suite-synthetic)
endif()

if(LIFTED_ENABLE_POLARIS AND POLARIS_CLANG_PATH AND EXISTS "${POLARIS_CLANG_PATH}" AND TARGET eval-suite-tum-simple-hash-functions)
    target_compile_definitions(lifted-tests PRIVATE
        EVAL_BKDRHASH_POLARIS_SO="${CMAKE_BINARY_DIR}/src/evaluation/tum/libeval-bkdrhash-polaris.so"
    )
    add_dependencies(lifted-tests eval-suite-tum-simple-hash-functions)
endif()
