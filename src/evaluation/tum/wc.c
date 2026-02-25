/*
 * wc.c  –  standalone stub for evaluation
 *
 * Pure-computation word/line/char counting over an in-memory buffer –
 * no stdio, no OS calls.  Link-clean .so.
 *
 * Entry points for lifting/verification:
 *   wc_lines(), wc_words(), wc_chars()
 */

#include <stddef.h>

typedef struct
{
    size_t lines;
    size_t words;
    size_t chars;
} WcResult;

/* Count newlines. */
size_t wc_lines(const char *buf, size_t n)
{
    size_t count = 0;
    for (size_t i = 0; i < n; i++)
        if (buf[i] == '\n')
            count++;
    return count;
}

/* Count whitespace-delimited words. */
size_t wc_words(const char *buf, size_t n)
{
    size_t count = 0;
    int in_word = 0;
    for (size_t i = 0; i < n; i++)
    {
        char c = buf[i];
        int ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
        if (!ws && !in_word)
        {
            count++;
            in_word = 1;
        }
        else if (ws)
        {
            in_word = 0;
        }
    }
    return count;
}

/* Total character count (just n). */
size_t wc_chars(const char *buf, size_t n)
{
    (void)buf;
    return n;
}

/* Combined: fills a WcResult struct. */
WcResult wc_all(const char *buf, size_t n)
{
    WcResult r;
    r.lines = wc_lines(buf, n);
    r.words = wc_words(buf, n);
    r.chars = wc_chars(buf, n);
    return r;
}
