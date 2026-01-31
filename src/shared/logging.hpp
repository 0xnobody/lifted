#pragma once

#include <cstdio>
#include <cstdarg>

namespace lifted
{

    // Simple logging helpers - will be replaced with proper logging library later
    // Using printf-style for now to keep it lightweight

    enum class log_level
    {
        error,
        warn,
        info,
        debug
    };

    namespace detail
    {
        inline void log_impl(log_level level, const char *fmt, ...)
        {
            const char *prefix = "";
            FILE *stream = stdout;

            switch (level)
            {
            case log_level::error:
                prefix = "[ERROR] ";
                stream = stderr;
                break;
            case log_level::warn:
                prefix = "[WARN] ";
                stream = stderr;
                break;
            case log_level::info:
                prefix = "[INFO] ";
                break;
            case log_level::debug:
                prefix = "[DEBUG] ";
                break;
            }

            fprintf(stream, "%s", prefix);

            va_list args;
            va_start(args, fmt);
            vfprintf(stream, fmt, args);
            va_end(args);

            fprintf(stream, "\n");
            fflush(stream);
        }
    }

    // Public logging interface - format will change when we move to fmt/spdlog
    inline void log_error(const char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "[ERROR] ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        fflush(stderr);
        va_end(args);
    }

    inline void log_warn(const char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "[WARN] ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        fflush(stderr);
        va_end(args);
    }

    inline void log_info(const char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        printf("[INFO] ");
        vprintf(fmt, args);
        printf("\n");
        fflush(stdout);
        va_end(args);
    }

    inline void log_debug(const char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        printf("[DEBUG] ");
        vprintf(fmt, args);
        printf("\n");
        fflush(stdout);
        va_end(args);
    }

} // namespace lifted
