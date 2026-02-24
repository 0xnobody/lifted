#pragma once

#include <cstdint>
#include <cstddef>

// Lightweight non-cryptographic hash mixing utilities.
//
// Uses the Murmur3 / finalizer mixing chain, which is fast and has excellent
// avalanche properties for use in hash chains and running hashes.
//
// Constants:
//   0x9e3779b97f4a7c15 — Fibonacci/golden-ratio-derived multiplier (Knuth)
//   0xff51afd7ed558ccd — Murmur3 64-bit finalizer multiplier

namespace lifted::hash
{
    // Mix two 64-bit values together using a multiply-xorshift chain.
    // Satisfies: mix(a, b) != mix(b, a) in general (order-sensitive).
    inline uint64_t mix(uint64_t a, uint64_t b) noexcept
    {
        uint64_t v = a ^ (b * 0x9e3779b97f4a7c15ULL);
        v ^= v >> 33;
        v *= 0xff51afd7ed558ccdULL;
        v ^= v >> 33;
        return v;
    }

    // Mix an arbitrary number of values into a seed.
    // Values are folded left-to-right: mix(mix(mix(seed, v0), v1), ...).
    template <typename... Ts>
    inline uint64_t mix_many(uint64_t seed, Ts... vals) noexcept
    {
        // Fold pack left-to-right using comma-based initializer trick.
        ((seed = mix(seed, static_cast<uint64_t>(vals))), ...);
        return seed;
    }

    // Mix raw bytes from a memory region into a seed.
    // Processes 8 bytes at a time (unaligned-safe via memcpy), then handles
    // the remaining tail.  Suitable for hashing variable-width memory values.
    inline uint64_t mix_bytes(uint64_t seed, const void *data, size_t n) noexcept
    {
        const auto *p = static_cast<const unsigned char *>(data);

        while (n >= 8)
        {
            uint64_t word = 0;
            __builtin_memcpy(&word, p, 8);
            seed = mix(seed, word);
            p += 8;
            n -= 8;
        }
        if (n > 0)
        {
            // Collect remaining bytes into a single word (little-endian)
            uint64_t tail = 0;
            for (size_t i = 0; i < n; ++i)
                tail |= static_cast<uint64_t>(p[i]) << (i * 8);
            seed = mix(seed, tail);
        }
        return seed;
    }

} // namespace lifted::hash
