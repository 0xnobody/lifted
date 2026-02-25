#pragma once

#include <unicorn/unicorn.h>
#include <utility>

namespace lifted::verif::uc
{
    // RAII wrapper for uc_engine*
    struct engine
    {
        uc_engine *handle = nullptr;

        engine() = default;
        explicit engine(uc_engine *h) : handle(h) {}

        engine(engine &&o) noexcept : handle(std::exchange(o.handle, nullptr)) {}
        engine &operator=(engine &&o) noexcept
        {
            if (this != &o)
            {
                reset();
                handle = std::exchange(o.handle, nullptr);
            }
            return *this;
        }

        engine(const engine &) = delete;
        engine &operator=(const engine &) = delete;

        ~engine() { reset(); }

        void reset()
        {
            if (handle)
            {
                uc_close(handle);
                handle = nullptr;
            }
        }

        uc_engine *get() const { return handle; }
        uc_engine *release() { return std::exchange(handle, nullptr); }
        explicit operator bool() const { return handle != nullptr; }
        uc_engine *operator->() const { return handle; }
    };

    // Factory for engine - returns error code, out param for engine
    inline uc_err open(uc_arch arch, uc_mode mode, engine &out)
    {
        uc_engine *h = nullptr;
        uc_err err = uc_open(arch, mode, &h);
        if (err == UC_ERR_OK)
        {
            out = engine(h);
        }
        return err;
    }

    // RAII wrapper for uc_context*
    struct context
    {
        uc_context *handle = nullptr;

        context() = default;
        explicit context(uc_context *h) : handle(h) {}

        context(context &&o) noexcept : handle(std::exchange(o.handle, nullptr)) {}
        context &operator=(context &&o) noexcept
        {
            if (this != &o)
            {
                reset();
                handle = std::exchange(o.handle, nullptr);
            }
            return *this;
        }

        context(const context &) = delete;
        context &operator=(const context &) = delete;

        ~context() { reset(); }

        void reset()
        {
            if (handle)
            {
                uc_context_free(handle);
                handle = nullptr;
            }
        }

        uc_context *get() const { return handle; }
        uc_context *release() { return std::exchange(handle, nullptr); }
        explicit operator bool() const { return handle != nullptr; }
    };

    // Factory for context - allocates from engine
    inline uc_err context_alloc(uc_engine *uc, context &out)
    {
        uc_context *h = nullptr;
        uc_err err = uc_context_alloc(uc, &h);
        if (err == UC_ERR_OK)
        {
            out = context(h);
        }
        return err;
    }

    // RAII wrapper for uc_hook (requires engine reference for deletion)
    struct hook
    {
        uc_engine *uc = nullptr;
        uc_hook handle = 0;

        hook() = default;
        hook(uc_engine *engine, uc_hook h) : uc(engine), handle(h) {}

        hook(hook &&o) noexcept : uc(o.uc), handle(std::exchange(o.handle, 0))
        {
            o.uc = nullptr;
        }
        hook &operator=(hook &&o) noexcept
        {
            if (this != &o)
            {
                reset();
                uc = o.uc;
                handle = std::exchange(o.handle, 0);
                o.uc = nullptr;
            }
            return *this;
        }

        hook(const hook &) = delete;
        hook &operator=(const hook &) = delete;

        ~hook() { reset(); }

        void reset()
        {
            if (uc && handle)
            {
                uc_hook_del(uc, handle);
                handle = 0;
                uc = nullptr;
            }
        }

        uc_hook get() const { return handle; }
        explicit operator bool() const { return handle != 0; }
    };

    // Variadic hook_add wrapper (type is int to allow bitwise OR of uc_hook_type)
    template <typename... Args>
    uc_err hook_add(uc_engine *uc, hook &out, int type, void *callback, void *user_data, Args... args)
    {
        uc_hook h = 0;
        uc_err err = uc_hook_add(uc, &h, type, callback, user_data, args...);
        if (err == UC_ERR_OK)
        {
            out = hook(uc, h);
        }
        return err;
    }

} // namespace lifted::uc
