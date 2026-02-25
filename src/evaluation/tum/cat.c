/*
 * cat.c  –  standalone stub for evaluation
 *
 * Reads bytes from one buffer and writes them to another buffer (simulating
 * cat's passthrough behaviour).  No stdio dependency so the .so links clean.
 *
 * Entry point for lifting/verification: cat_buf()
 */

#include <stddef.h>

/* Copy n bytes from src to dst, return number of bytes copied. */
size_t cat_buf(const char *src, char *dst, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
    {
        dst[i] = src[i];
        if (src[i] == '\0')
            break;
    }
    return i;
}

/* Count bytes until NUL (strlen equivalent). */
size_t cat_strlen(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0')
        n++;
    return n;
}

/* Reverse a buffer in-place. */
void cat_rev(char *buf, size_t n)
{
    size_t lo = 0, hi = n - 1;
    while (lo < hi)
    {
        char tmp = buf[lo];
        buf[lo] = buf[hi];
        buf[hi] = tmp;
        lo++;
        hi--;
    }
}
