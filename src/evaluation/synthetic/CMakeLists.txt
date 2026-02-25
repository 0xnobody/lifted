# ── Synthetic Evaluation Suite ────────────────────────────────────────────────
# Migrated to the EvalHelpers API (define_eval_target + define_eval_suite).
# Previously used set_optimized_target() / set_polaris_target() helpers.

project("lifted-eval-synthetic")

set(EVAL_SYNTHETIC_LIBS
    arithmetic
    branch
    ext-call-branching
    ext-call
    indirect-call
    local-vars
    loop-bounded
    loop-unbounded
    stack-args
    stack-loop
    switch
    test
    ext-call-stack-args
)

# ── Define one target per source file ─────────────────────────────────────────
foreach(_lib IN LISTS EVAL_SYNTHETIC_LIBS)
    define_eval_target(
        NAME    "${_lib}"
        SOURCE  "${_lib}.cpp"
        LANGUAGE CXX
    )
endforeach()

# ── Assemble the suite (also builds Polaris variants if registered) ────────────
define_eval_suite(
    NAME      synthetic
    TARGETS   ${EVAL_SYNTHETIC_LIBS}
    #OBFUSCATORS polaris
)

# ── Backward-compat cache variables ───────────────────────────────────────────
# Keep EVAL_SYNTHETIC_LIBS_DIR so that any code still referencing it continues
# to work unchanged.
set(EVAL_SYNTHETIC_LIBS_DIR
    "${CMAKE_CURRENT_BINARY_DIR}"
    CACHE STRING "Directory containing synthetic evaluation shared libraries" FORCE)