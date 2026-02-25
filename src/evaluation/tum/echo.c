/*
 * echo.c  –  standalone stub for evaluation
 *
 * In-memory string operations mirroring echo's behaviour (concatenation,
 * optional newline appending).  No stdio dependency.
 *
 * Entry points for lifting/verification:
 *   echo_copy(), echo_concat(), echo_append_newline()
 */

#include <stddef.h>

/* Copy src into dst (NUL-terminated), return length written (excl. NUL). */
size_t echo_copy(const char *src, char *dst, size_t dst_cap)
{
    size_t i = 0;
    while (i + 1 < dst_cap && src[i] != '\0')
    {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

/*
 * Concatenate two strings into dst with a space separator.
 * Returns total length written (excl. NUL), or 0 if dst_cap too small.
 */
size_t echo_concat(const char *a, const char *b, char *dst, size_t dst_cap)
{
    size_t i = 0;

    /* copy a */
    while (i + 1 < dst_cap && a[i] != '\0')
    {
        dst[i] = a[i];
        i++;
    }

    /* space separator */
    if (i + 1 < dst_cap)
        dst[i++] = ' ';

    /* copy b */
    size_t j = 0;
    while (i + 1 < dst_cap && b[j] != '\0')
    {
        dst[i++] = b[j++];
    }

    dst[i] = '\0';
    return i;
}

/*
 * Append a newline to a NUL-terminated string in buf (in-place).
 * Returns new length, or 0 if no room.
 */
size_t echo_append_newline(char *buf, size_t len, size_t cap)
{
    if (len + 2 > cap)
        return 0;
    buf[len] = '\n';
    buf[len + 1] = '\0';
    return len + 1;
}
