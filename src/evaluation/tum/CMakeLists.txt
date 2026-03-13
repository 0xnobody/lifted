# ── TUM Obfuscation Benchmarks ────────────────────────────────────────────────
# Fetches https://github.com/tum-i4/obfuscation-benchmarks at configure time
# and creates evaluation suites for three sub-directories:
#   • small-programs          (48 parameterised programs varying CF complexity)
#   • basic-algorithms        (CS101 algorithms: factorial, gcd, sort, …)
#   • simple-hash-functions   (non-cryptographic hash functions)
#
# Tigress-generated programs are intentionally excluded.

project("lifted-eval-tum")

include(FetchContent)

# ── Fetch the benchmark repo ──────────────────────────────────────────────────
# The repo contains no CMakeLists.txt so we use FetchContent_Populate to just
# download the sources without trying to add_subdirectory() them.
FetchContent_Declare(
    tum_benchmarks
    GIT_REPOSITORY https://github.com/tum-i4/obfuscation-benchmarks.git
    GIT_TAG        d11452ffb3ec7418a462f65d4034f9f1474136c8
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(tum_benchmarks)
if(NOT tum_benchmarks_POPULATED)
    FetchContent_Populate(tum_benchmarks)
endif()

set(_TUM_ROOT "${tum_benchmarks_SOURCE_DIR}")
message(STATUS "[tum-eval] Benchmark sources: ${_TUM_ROOT}")

# ── Internal helper: glob a sub-directory, define one target per .c file ─────
# Usage: _tum_define_suite(<suite-name> <subdir-relative-to-root>)
macro(_tum_define_suite SUITE_NAME SUBDIR)
    file(GLOB _tum_sources CONFIGURE_DEPENDS "${_TUM_ROOT}/${SUBDIR}/*.c")

    if(NOT _tum_sources)
        message(WARNING "[tum-eval] No .c files found in ${_TUM_ROOT}/${SUBDIR}")
    endif()

    set(_tum_targets "")
    foreach(_src IN LISTS _tum_sources)
        get_filename_component(_tname "${_src}" NAME_WE)
        define_eval_target(NAME "${_tname}" SOURCE "${_src}" LANGUAGE C)
        list(APPEND _tum_targets "${_tname}")
    endforeach()

    define_eval_suite(
        NAME    "${SUITE_NAME}"
        TARGETS ${_tum_targets}
    )
endmacro()

# ── Build the three suites ────────────────────────────────────────────────────
_tum_define_suite(tum-small-programs       small-programs)
_tum_define_suite(tum-basic-algorithms     basic-algorithms)
_tum_define_suite(tum-simple-hash-functions simple-hash-functions)
