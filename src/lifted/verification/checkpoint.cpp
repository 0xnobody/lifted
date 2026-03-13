#include "checkpoint.hpp"

#include "../hash_mix.hpp"

#include <remill/Arch/X86/Runtime/State.h>

namespace lifted::verification
{
    uint64_t checkpoint_record_t::hash_state(const State *s) noexcept
    {
        return hash::mix_many(
            0ULL,
            s->gpr.rax.qword,
            s->gpr.rbx.qword,
            s->gpr.rcx.qword,
            s->gpr.rdx.qword,
            s->gpr.rsi.qword,
            s->gpr.rdi.qword,
            s->gpr.rbp.qword,
            s->gpr.rsp.qword,
            s->gpr.r8.qword,
            s->gpr.r9.qword,
            s->gpr.r10.qword,
            s->gpr.r11.qword,
            s->gpr.r12.qword,
            s->gpr.r13.qword,
            s->gpr.r14.qword,
            s->gpr.r15.qword
            // static_cast<uint64_t>(s->rflag.flat) TODO: add handling of undefined flags
        );
    }

    uint64_t checkpoint_record_t::compose_combined_hash(const checkpoint_t &cp,
                                                        size_t index,
                                                        compare_dimension_flags dims) noexcept
    {
        uint64_t acc = 0;
        if (has_flag(dims, compare_dimension_flags::REG_STATE))
            acc = hash::mix(acc, cp.state_hash);
        if (has_flag(dims, compare_dimension_flags::BB_TRACE))
            acc = hash::mix(acc, cp.bb_trace_hash);
        if (has_flag(dims, compare_dimension_flags::WRITE_SEQUENCE))
            acc = hash::mix(acc, cp.mem_write_hash);
        if (has_flag(dims, compare_dimension_flags::MEM_CONTENTS))
            acc = hash::mix(acc, cp.memory_contents_hash);
        if (has_flag(dims, compare_dimension_flags::READ_SEQUENCE))
            acc = hash::mix(acc, cp.read_hash);
        if (has_flag(dims, compare_dimension_flags::EXT_CALLS))
            acc = hash::mix(acc, cp.ext_call_hash);
        return hash::mix(acc, static_cast<uint64_t>(index));
    }

    uint64_t checkpoint_record_t::push_bb(uint64_t rva, const State *s, uint64_t memory_contents_hash)
    {
        checkpoint_t cp = checkpoints.back();
        const size_t index = checkpoints.size();

        cp.state_hash = hash::mix(cp.state_hash, hash_state(s));
        cp.bb_trace_hash = hash::mix(cp.bb_trace_hash, rva);
        cp.memory_contents_hash = memory_contents_hash;
        cp.combined_hash = compose_combined_hash(cp, index, compare_dims);
        checkpoints.push_back(cp);
        bb_counts.push_back(bb_counts.back() + 1u);

        if (record_details)
            details.push_back({checkpoint_detail_t::kind::BB, rva, 0, 0,
                               s ? std::optional<State>(*s) : std::nullopt});

        return cp.combined_hash;
    }

    uint64_t checkpoint_record_t::push_write(uint64_t addr,
                                             uint64_t value,
                                             uint32_t size,
                                             uint64_t memory_contents_hash)
    {
        checkpoint_t cp = checkpoints.back();
        const size_t index = checkpoints.size();

        cp.mem_write_hash = hash::mix_many(cp.mem_write_hash, addr, value, static_cast<uint64_t>(size));
        cp.memory_contents_hash = memory_contents_hash;
        cp.combined_hash = compose_combined_hash(cp, index, compare_dims);
        checkpoints.push_back(cp);
        bb_counts.push_back(bb_counts.back());
        ++mem_write_count;

        if (record_details)
            details.push_back({checkpoint_detail_t::kind::MEM_WRITE, addr, value, size, std::nullopt});

        return cp.combined_hash;
    }

    uint64_t checkpoint_record_t::push_read(uint64_t addr,
                                            uint64_t value,
                                            uint32_t size,
                                            uint64_t memory_contents_hash)
    {
        checkpoint_t cp = checkpoints.back();
        const size_t index = checkpoints.size();

        cp.read_hash = hash::mix_many(cp.read_hash, addr, value, static_cast<uint64_t>(size));
        cp.memory_contents_hash = memory_contents_hash;
        cp.combined_hash = compose_combined_hash(cp, index, compare_dims);
        checkpoints.push_back(cp);
        bb_counts.push_back(bb_counts.back());
        ++read_count;

        if (record_details)
            details.push_back({checkpoint_detail_t::kind::MEM_READ, addr, value, size, std::nullopt});

        return cp.combined_hash;
    }

    uint64_t checkpoint_record_t::push_ext_call(uint64_t addr, const State *s, uint64_t memory_contents_hash)
    {
        checkpoint_t cp = checkpoints.back();
        const size_t index = checkpoints.size();

        cp.state_hash = hash::mix(cp.state_hash, hash_state(s));
        cp.ext_call_hash = hash::mix(cp.ext_call_hash, addr);
        cp.memory_contents_hash = memory_contents_hash;
        cp.combined_hash = compose_combined_hash(cp, index, compare_dims);
        checkpoints.push_back(cp);
        bb_counts.push_back(bb_counts.back());
        ++ext_call_count;

        if (record_details)
            details.push_back({checkpoint_detail_t::kind::EXT_CALL, addr, 0, 0,
                               s ? std::optional<State>(*s) : std::nullopt});

        return cp.combined_hash;
    }

} // namespace lifted::verification
