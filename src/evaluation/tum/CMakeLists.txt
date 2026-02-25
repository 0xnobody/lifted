# ── TUM Evaluation Suite ──────────────────────────────────────────────────────
# A suite of real-world utility binaries for evaluation.
#
# Currently seeded with lightweight standalone C implementations of common
# Unix utilities.  Replace or extend with actual coreutils sources by pointing
# SOURCE at the coreutils .c file and adjusting COMPILE_OPTIONS as needed.

project("lifted-eval-tum")

# ── Define targets ────────────────────────────────────────────────────────────
define_eval_target(NAME cat    SOURCE cat.c    LANGUAGE C)
define_eval_target(NAME wc     SOURCE wc.c     LANGUAGE C)
define_eval_target(NAME echo   SOURCE echo.c   LANGUAGE C)

# ── Assemble the suite ────────────────────────────────────────────────────────
define_eval_suite(
    NAME      tum-eval
    TARGETS   cat wc echo
    OBFUSCATORS polaris
)
