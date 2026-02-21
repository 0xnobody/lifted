#include "checkpoint.hpp"

#include <lifted/hash_mix.hpp>

#include <remill/Arch/X86/Runtime/State.h>

namespace lifted::verification
{
    // ── checkpoint_record_t::hash_state ──────────────────────────────────────
    //
    // Hashes only the 16 named GPRs + rflag.flat.  Avoids the full State struct
    // so uninitialised/padding bytes in vector registers, segment registers, etc.
    // cannot produce false divergence between records.

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
            s->gpr.r15.qword,
            static_cast<uint64_t>(s->rflag.flat));
    }

    // ── push helpers ──────────────────────────────────────────────────────────

    uint64_t checkpoint_record_t::push_bb(uint64_t rva, const State *s)
    {
        checkpoint_t cp = checkpoints.back();
        size_t index = checkpoints.size();

        cp.state_hash = hash::mix(cp.state_hash, hash::mix(hash_state(s), rva));
        cp.combined_hash = make_combined(cp, index);
        checkpoints.push_back(cp);
        return cp.combined_hash;
    }

    uint64_t checkpoint_record_t::push_write(uint64_t addr, uint64_t value, uint32_t size)
    {
        checkpoint_t cp = checkpoints.back();
        size_t index = checkpoints.size();

        cp.mem_write_hash = hash::mix_many(cp.mem_write_hash, addr, value,
                                           static_cast<uint64_t>(size));
        cp.combined_hash = make_combined(cp, index);
        checkpoints.push_back(cp);
        return cp.combined_hash;
    }

    uint64_t checkpoint_record_t::push_read(uint64_t addr, uint64_t value, uint32_t size)
    {
        checkpoint_t cp = checkpoints.back();
        size_t index = checkpoints.size();

        cp.read_hash = hash::mix_many(cp.read_hash, addr, value,
                                      static_cast<uint64_t>(size));
        cp.combined_hash = make_combined(cp, index);
        checkpoints.push_back(cp);
        return cp.combined_hash;
    }

    uint64_t checkpoint_record_t::push_ext_call(uint64_t addr, const State *s)
    {
        checkpoint_t cp = checkpoints.back();
        size_t index = checkpoints.size();

        cp.ext_call_hash = hash::mix(cp.ext_call_hash, hash::mix(hash_state(s), addr));
        cp.combined_hash = make_combined(cp, index);
        checkpoints.push_back(cp);
        return cp.combined_hash;
    }

} // namespace lifted::verification
