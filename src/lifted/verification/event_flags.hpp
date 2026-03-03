#pragma once

#include <cstdint>

namespace lifted::verification
{
    enum class event_flags : uint32_t
    {
        NONE = 0,
        BB = 1 << 0,
        MEM_WRITE = 1 << 1,
        MEM_READ = 1 << 2,
        EXT_CALL = 1 << 3,

        // Default: BB + MEM_WRITE + EXT_CALL  (reads off by default)
        DEFAULT = BB | MEM_WRITE | EXT_CALL,
    };

    inline event_flags operator|(event_flags a, event_flags b) noexcept
    {
        return static_cast<event_flags>(
            static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
    }

    inline event_flags operator&(event_flags a, event_flags b) noexcept
    {
        return static_cast<event_flags>(
            static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
    }

    inline bool has_flag(event_flags set, event_flags flag) noexcept
    {
        return (static_cast<uint32_t>(set) & static_cast<uint32_t>(flag)) != 0;
    }
} // namespace lifted::verification
