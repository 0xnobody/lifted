# ── Evaluation Suite Infrastructure ──────────────────────────────────────────
# Include the shared EvalHelpers module before any sub-suites so that
# define_eval_target() / define_eval_suite() / register_obfuscator() are
# available everywhere.

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/EvalHelpers.cmake")

# ── Register known obfuscators ────────────────────────────────────────────────
# Polaris is configured by BuildPolaris.cmake.  We register it here so all
# suites can opt in via  OBFUSCATORS polaris  in define_eval_suite().
if(POLARIS_CLANG_PATH AND EXISTS "${POLARIS_CLANG_PATH}")
    register_obfuscator(NAME polaris
        COMPILER "${POLARIS_CLANG_PATH}"
        FLAGS    "-mllvm -passes=${POLARIS_PASSES}"
    )
endif()

# ── Evaluation suites ─────────────────────────────────────────────────────────
add_subdirectory(synthetic)
add_subdirectory(tum)