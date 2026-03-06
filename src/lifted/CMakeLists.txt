project(lifted)

# ── Static library: all sources except main.cpp ──────────────────────────────

add_library(lifted STATIC
    "helpers.cpp"
    "helpers.hpp"
    "utils.hpp"
    "utils.cpp"
    "opt.hpp"
    "opt.cpp"
    "slicer.cpp"
    "slicer.hpp"

    "compat/lief_compat.hpp"

    "lifter/lifter_types.hpp"
    "lifter/lift_context.hpp"
    "lifter/lifter_utils.hpp"
    "lifter/lifter_utils.cpp"
    "lifter/lifter_callbacks.hpp"
    "lifter/lifter_callbacks.cpp"
    "lifter/standard_lifter_callbacks.hpp"
    "lifter/standard_lifter_callbacks.cpp"
    "lifter/lifter.hpp"
    "lifter/lifter.cpp"
    "lifter/cfg.cpp"

    "passes/pass_utils.cpp"
    "passes/pass_utils.hpp"

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
    "pipeline/stages/time_budget_stage.hpp"
    "pipeline/stages/time_budget_stage.cpp"
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
    "HELPERS_ABI_PATH=\"${HELPERS_ABI_PATH}\""
    "HELPERS_LIFTING_PATH=\"${HELPERS_LIFTING_PATH}\""
    "HELPERS_RAM_PATH=\"${HELPERS_RAM_PATH}\""
)

add_dependencies(lifted helpers z3_external)
