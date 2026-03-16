project(lifted)

# ── Static library: all sources except main.cpp ──────────────────────────────

add_library(lifted STATIC
    "helpers.cpp"
    "helpers.hpp"
    "utils.hpp"
    "utils.cpp"
    "opt.hpp"
    "opt.cpp"
    "binary_context.hpp"
    "binary_context.cpp"

    "compat/lief_compat.hpp"

    "lifter/lifter_types.hpp"
    "lifter/lift_context.hpp"
    "lifter/lifter_utils.hpp"
    "lifter/lifter_utils.cpp"
    "lifter/helper_state_annotations.hpp"
    "lifter/helper_state_annotations.cpp"
    "lifter/lifter_callbacks.hpp"
    "lifter/lifter_callbacks.cpp"
    "lifter/standard_lifter_callbacks.hpp"
    "lifter/standard_lifter_callbacks.cpp"
    "lifter/polaris_lifter_callbacks.hpp"
    "lifter/polaris_lifter_callbacks.cpp"
    "lifter/lifter.hpp"
    "lifter/lifter.cpp"
    "lifter/cfg.cpp"

    "passes/pass_utils.cpp"
    "passes/pass_utils.hpp"

    "passes/deobfuscation/constant_memory_folding_pass.cpp"
    "passes/deobfuscation/constant_memory_folding_pass.hpp"

    "passes/verification/memory_intrinsic_lowering_pass.cpp"
    "passes/verification/memory_intrinsic_lowering_pass.hpp"

    "abi/calling_convention.hpp"
    "abi/calling_convention.cpp"
    "abi/all_registers_cc.hpp"
    "abi/all_registers_cc.cpp"
    "abi/systemv_x64.hpp"
    "abi/abi_utils.hpp"
    "abi/abi_utils.cpp"
    "abi/function_state_attrs.hpp"
    "abi/function_state_attrs.cpp"
    "abi/state_fold.hpp"
    "abi/state_fold.cpp"

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

    # Pipeline framework
    "pipeline/run_config.hpp"
    "pipeline/corpus.hpp"
    "pipeline/corpus.cpp"
    "pipeline/stage.hpp"
    "pipeline/pipeline.hpp"
    "pipeline/pipeline.cpp"
    "pipeline/deep_dive.hpp"
    "pipeline/deep_dive.cpp"
    "pipeline/stages/seed_sweep_stage.hpp"
    "pipeline/stages/seed_sweep_stage.cpp"
    "pipeline/stages/corpus_replay_stage.hpp"
    "pipeline/stages/corpus_replay_stage.cpp"

    # Visualization
    "visualization/cfg_data.hpp"
    "visualization/dot_helpers.hpp"
    "visualization/cfg_dot.hpp"
    "visualization/cfg_dot.cpp"
    "visualization/pipeline_overlay.hpp"
    "visualization/pipeline_overlay.cpp"
)

# Expose src/lifted/ as a public include root so consumers can do:
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
    "HELPERS_LIFTING_PATH=\"${HELPERS_LIFTING_PATH}\""
    "HELPERS_RAM_PATH=\"${HELPERS_RAM_PATH}\""
)

add_dependencies(lifted helpers z3_external)
