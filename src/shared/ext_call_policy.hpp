#pragma once

#include <cstdint>
#include <vector>
#include <optional>

namespace lifted
{
    struct ext_call_info_t
    {
        enum class CALLCONV
        {
            MSVC_X64,
            SYSTEMV_X64
        };

        struct param_t
        {
            size_t size;
            // bool is_pointer;
        };

        uint64_t target_rva;
        CALLCONV callconv;
        std::vector<param_t> params;
        size_t return_size;
    };

    class ext_call_policy
    {
    public:
        virtual ~ext_call_policy() = default;

        // Given an external call target address, return information about the call
        // (or nullopt if unknown/unhandled).
        virtual std::optional<ext_call_info_t> check_block_entry(uint64_t target_rva) const
        {
            return std::nullopt;
        }

        virtual std::optional<ext_call_info_t> check_callsite(uint64_t callsite_rva) const
        {
            return std::nullopt;
        }
    };
}