/* Minimal gnulib config.h for x86-64 Linux in the lifted eval suite.
   Replaces the autoconf-generated config.h for the specific modules used here.
   Add new defines as additional gnulib modules are onboarded.

   Three categories of defines:
   1. Gnulib infrastructure macros (would normally come from AC_DEFINE in configure.ac)
   2. alignof portability (C17 needs <stdalign.h> for the macro)
   3. Feature flags for the specific modules being compiled
*/
#pragma once

/* ── 1. Gnulib infrastructure ─────────────────────────────────────────────── */

/* Token that gnulib headers use to verify config.h was included first. */
#define _GL_CONFIG_H_INCLUDED 1

/* Inline function semantics: use standard C99 inline. GCC 11 with gnu17
   (default) has __GNUC_STDC_INLINE__ set, so the inline keyword is standard. */
#define _GL_INLINE             inline
#define _GL_EXTERN_INLINE      extern inline
#define _GL_EXTERN_INLINE_IN_USE

/* Diagnostic push/pop guards for inline-function headers.  GCC >= 5 leaves
   these empty; GCC 4.6–4.9 would suppress some spurious prototype warnings.
   We target GCC 11, so both macros are empty. */
#define _GL_INLINE_HEADER_BEGIN
#define _GL_INLINE_HEADER_END

/* GCC attribute macros.  gnulib's autoconf generates these in config.h via
   gnulib-common.m4.  We define only the subset that the compiled modules
   (crc, md5, sha1, sha256, sha512) actually need. */
#ifdef __GNUC__
# define _GL_ATTRIBUTE_PURE  __attribute__ ((__pure__))
# define _GL_ATTRIBUTE_CONST __attribute__ ((__const__))
# define _GL_ATTRIBUTE_MAYBE_UNUSED __attribute__ ((__unused__))
#else
# define _GL_ATTRIBUTE_PURE
# define _GL_ATTRIBUTE_CONST
# define _GL_ATTRIBUTE_MAYBE_UNUSED
#endif

/* ── 2. alignof portability ──────────────────────────────────────────────── */

/* alignof is a C23 keyword; in C17 / gnu17 it requires <stdalign.h>.
   gnulib uses alignof(...) directly in md5.c, sha1.c, sha256.c, sha512.c. */
#include <stdalign.h>

/* ── 3. Module feature flags ─────────────────────────────────────────────── */

/* Disable OpenSSL backends — use gnulib's own pure-C implementations. */
#define HAVE_OPENSSL_MD5    0
#define HAVE_OPENSSL_SHA1   0
#define HAVE_OPENSSL_SHA256 0
#define HAVE_OPENSSL_SHA512 0

/* Do NOT define GL_CRC_X86_64_PCLMUL here: crc.c guards with #ifdef (not #if),
 * so defining it to 0 still triggers the PCLMUL include path.  Leaving it
 * undefined disables the AVX/PCLMUL path correctly. */
/* Disable slice-by-8 CRC; keeps the scalar 256-entry table path only. */
#define GL_CRC_SLICE_BY_8    0
