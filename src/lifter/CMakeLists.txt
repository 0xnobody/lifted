project(lifted)

add_executable(lifted 
    "main.cpp"
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
    "verification/verifier_state.hpp"
    "verification/verifier_context.hpp"
    "verification/paged_memory_state.hpp"
    "verification/paged_memory_state.cpp"
    "verification/execution_result.hpp"
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
    "verification/test_generator.hpp"
    "verification/test_generator.cpp"
    "verification/runner.hpp"
    "verification/runner.cpp"
    "verification/examples.hpp"
    "verification/examples.cpp"
    "third-party/nmd_assembly.h" # for testing
    "third-party/nmd_assembly.cpp"
)

target_link_libraries(lifted PRIVATE
    remill
    LIEF::LIEF
    libklee
    Souper
    lifted-shared
    LLVMOrcJIT
    unicorn_external
)

target_compile_definitions(lifted PRIVATE
    "HELPERS_DEOBFUSCATION_INTRINSICS_PATH=\"${HELPERS_DEOBFUSCATION_INTRINSICS_PATH}\""
    "HELPERS_VERIFICATION_INTRINSICS_PATH=\"${HELPERS_VERIFICATION_INTRINSICS_PATH}\""
    "HELPERS_STATE_UTILS_PATH=\"${HELPERS_STATE_UTILS_PATH}\""
    "EVAL_SYNTHETIC_LIBS_DIR=\"${EVAL_SYNTHETIC_LIBS_DIR}\""
    "KLEE_RUNTIME_LIBRARY_PATH=\"${KLEE_RUNTIME_LIBRARY_PATH}\""
    "HELPERS_ABI_PATH=\"${HELPERS_ABI_PATH}\""
    "HELPERS_LIFTING_PATH=\"${HELPERS_LIFTING_PATH}\""
)

# Ensure Z3 is built before linking
add_dependencies(lifted helpers z3_external lifted-shared)