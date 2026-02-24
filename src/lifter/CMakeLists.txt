project(lifted)

# ── Static library: all sources except main.cpp ──────────────────────────────

add_library(lifted STATIC
    "tester.cpp"
    "tester.hpp"
    "helpers.cpp"
    "helpers.hpp"
    "utils.hpp"
    "utils.cpp"
    "opt.hpp"
    "opt.cpp"
    "slicer.cpp"
    "slicer.hpp"
    "lifter2.cpp"
    "lifter2.hpp"

    "passes/pass_utils.cpp"
    "passes/pass_utils.hpp"

    "passes/redefine_external_calls_pass.cpp"
    "passes/redefine_external_calls_pass.hpp"

    "passes/deobfuscation/ram_direct_access_pass.cpp"
    "passes/deobfuscation/canonicalize_stack_pass.cpp"
    "passes/deobfuscation/canonicalize_stack_pass.hpp"
    "passes/deobfuscation/constant_memory_folding_pass.cpp"
    "passes/deobfuscation/constant_memory_folding_pass.hpp"

    "passes/verification/memory_intrinsic_lowering_pass.cpp"
    "passes/verification/memory_intrinsic_lowering_pass.hpp"

    "passes/analysis/stack_aa_pass.cpp"
    "passes/analysis/stack_aa_pass.hpp"

    "abi/calling_convention.hpp"
    "abi/calling_convention.cpp"
    "abi/systemv_x64.hpp"
    "abi/abi_utils.hpp"
    "abi/abi_utils.cpp"

    # Verification framework
    "verification/sentinel_oracle.hpp"
    "verification/verifier_state.hpp"
    "verification/verifier_context.hpp"
    "verification/paged_memory_state.hpp"
    "verification/paged_memory_state.cpp"
    "verification/executor.hpp"
    "verification/unicorn_executor.hpp"
    "verification/unicorn_executor.cpp"
    "verification/jit_executor.hpp"
    "verification/jit_executor.cpp"
    "verification/state_conversion.hpp"
    "verification/state_conversion.cpp"
    "verification/uc_raii.hpp"
    "verification/comparator.hpp"
    "verification/comparator.cpp"
    "verification/checkpoint.hpp"
    "verification/checkpoint.cpp"
    "third-party/nmd_assembly.h"
    "third-party/nmd_assembly.cpp"
)

# Expose src/lifter/ as a public include root so consumers can do:
#   #include "verification/paged_memory_state.hpp"  etc.
target_include_directories(lifted PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(lifted
    PUBLIC
        remill
        LIEF::LIEF
        libklee
        Souper
        LLVMOrcJIT
        unicorn_external
)

target_compile_definitions(lifted PRIVATE
    "HELPERS_DEOBFUSCATION_INTRINSICS_PATH=\"${HELPERS_DEOBFUSCATION_INTRINSICS_PATH}\""
    "HELPERS_VERIFICATION_INTRINSICS_PATH=\"${HELPERS_VERIFICATION_INTRINSICS_PATH}\""
    "HELPERS_STATE_UTILS_PATH=\"${HELPERS_STATE_UTILS_PATH}\""
    "KLEE_RUNTIME_LIBRARY_PATH=\"${KLEE_RUNTIME_LIBRARY_PATH}\""
    "HELPERS_ABI_PATH=\"${HELPERS_ABI_PATH}\""
    "HELPERS_LIFTING_PATH=\"${HELPERS_LIFTING_PATH}\""
)

add_dependencies(lifted helpers z3_external)

# ── Main executable ───────────────────────────────────────────────────────────

add_executable(lifted_exe "main.cpp")

set_target_properties(lifted_exe PROPERTIES OUTPUT_NAME lifted)

target_link_libraries(lifted_exe PRIVATE lifted)

# main.cpp uses EVAL_SYNTHETIC_LIBS_DIR directly
target_compile_definitions(lifted_exe PRIVATE
    "EVAL_SYNTHETIC_LIBS_DIR=\"${EVAL_SYNTHETIC_LIBS_DIR}\""
)

# ── Tests executable ──────────────────────────────────────────────────────────

add_executable(lifted_tests
    "tests/test_main.cpp"
    "tests/test_sentinel_oracle.cpp"
    "tests/test_paged_memory.cpp"
    "tests/test_checkpoint.cpp"
    "tests/test_comparator.cpp"
    "tests/test_comparator_diff.cpp"
)

target_link_libraries(lifted_tests PRIVATE lifted)
