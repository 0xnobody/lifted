# ── GNU Coreutils / gnulib Algorithm Suite ────────────────────────────────────
# Fetches https://github.com/coreutils/gnulib at a pinned commit and compiles
# selected algorithmic library modules as eval targets.
#
# Source: gnulib lib/ directory — the pure-computation subset used by coreutils
# utilities such as md5sum, sha256sum, sha512sum, sha1sum, cksum.
#
# No autoconf/configure step is required.  gnulib's <config.h> dependency is
# satisfied by a committed stub at gnulib-stub/config.h.

project("lifted-eval-coreutils")

include(FetchContent)

# ── Fetch gnulib at pinned SHA ────────────────────────────────────────────────
FetchContent_Declare(
    coreutils_gnulib
    GIT_REPOSITORY https://github.com/coreutils/gnulib.git
    GIT_TAG        d5f683434d1a288940c6d98ac0f24b834e277fc2
)
FetchContent_GetProperties(coreutils_gnulib)
if(NOT coreutils_gnulib_POPULATED)
    FetchContent_Populate(coreutils_gnulib)
endif()

set(_GNULIB "${coreutils_gnulib_SOURCE_DIR}/lib")
message(STATUS "[coreutils-eval] gnulib sources: ${_GNULIB}")

# ── Shared compile options for all gnulib targets ─────────────────────────────
# 1. gnulib-stub/ provides config.h (autoconf replacement) and endian.h stub.
# 2. ${_GNULIB} provides module headers (md5.h, sha256.h, crc.h, ...).
# These are prepended so they shadow any stale system/build-dir headers.
set(_GNULIB_OPTS
    -I${CMAKE_CURRENT_SOURCE_DIR}/gnulib-stub
    -I${_GNULIB}
    -Wno-unused-function
    -Wno-unused-variable
)

# ── Eval targets ──────────────────────────────────────────────────────────────

define_eval_target(NAME gnulib-md5 SOURCE "${_GNULIB}/md5.c" LANGUAGE C
    COMPILE_OPTIONS ${_GNULIB_OPTS}
    FUNCTIONS md5_buffer md5_process_block md5_process_bytes md5_finish_ctx)

define_eval_target(NAME gnulib-sha1 SOURCE "${_GNULIB}/sha1.c" LANGUAGE C
    COMPILE_OPTIONS ${_GNULIB_OPTS}
    FUNCTIONS sha1_buffer sha1_process_block sha1_process_bytes sha1_finish_ctx)

define_eval_target(NAME gnulib-sha256 SOURCE "${_GNULIB}/sha256.c" LANGUAGE C
    COMPILE_OPTIONS ${_GNULIB_OPTS}
    FUNCTIONS sha256_buffer sha256_process_block sha256_process_bytes
              sha256_finish_ctx sha224_buffer)  # sha224_process_block does not exist;

define_eval_target(NAME gnulib-sha512 SOURCE "${_GNULIB}/sha512.c" LANGUAGE C
    COMPILE_OPTIONS ${_GNULIB_OPTS}
    FUNCTIONS sha512_buffer sha512_process_block sha512_process_bytes
              sha512_finish_ctx sha384_buffer)

define_eval_target(NAME gnulib-crc SOURCE "${_GNULIB}/crc.c" LANGUAGE C
    COMPILE_OPTIONS ${_GNULIB_OPTS}
    FUNCTIONS crc32 crc32_update crc32_update_no_xor crc32_no_xor)

# ── Suite assembly ────────────────────────────────────────────────────────────
# To add more gnulib targets later: add a define_eval_target() above and
# append the NAME to the TARGETS list here.

define_eval_suite(
    NAME    gnu-coreutils
    TARGETS gnulib-md5
            gnulib-sha1
            gnulib-sha256
            gnulib-sha512
            gnulib-crc
)
