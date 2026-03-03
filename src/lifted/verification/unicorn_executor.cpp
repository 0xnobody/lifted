#include "unicorn_executor.hpp"

#include "../utils.hpp"

#include <mutex>
#include <sstream>
#include <vector>

// XED headers have no extern "C" guards, so wrap them to prevent
// C++ name mangling of XED's non-inline API functions.
extern "C"
{
#include <xed/xed-interface.h>
}

namespace lifted::verification
{
    struct unicorn_ctx_t
    {
        UnicornExecutor *executor;
        verifier_state *state;
        uint64_t prev_block = 0;
        uint32_t prev_size = 0;
    };

    // Helper to create Unicorn error messages
    static llvm::Error uc_error(const char *operation, uc_err err)
    {
        std::ostringstream msg;
        msg << operation << " failed: " << uc_strerror(err);
        return llvm::make_error<llvm::StringError>(msg.str(), llvm::inconvertibleErrorCode());
    }

    // Hook callbacks

    // From Unicorn:
    // > NOTE: This is different from UC_HOOK_BLOCK in 2 ways:
    // > 1. The hook is called before executing code.
    // > 2. The hook is only called when generation is triggered.
    //
    // TCG (QEMU's Tiny Code Generator) has some quirks:
    // 1. Consider:
    //
    // 0x0: ins1
    // 0x1: rep ins2
    // 0x2: ins3
    // 0x3: ins4
    // ...
    //
    // Will fire: (0x0-0x1), then (0x1) for each rep, and finally (0x2, 0x...)
    // In reality this is a single BB starting at 0x0. So we must deduplicate this.
    //
    // - If the blocks overlap, we must classify them as 'real' or 'fake' blocks
    // - If 'fake', we add it to ignore list (known 'rep' instructions)
    //
    void UnicornExecutor::hook_edge(uc_engine *uc, uc_tb *cur_tb, uc_tb *prev_tb, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);

        if (!cur_tb)
            return;

        if (!prev_tb)
        {
            return;
        }

        const uint64_t prev_start = prev_tb->pc;
        const uint64_t prev_end = prev_tb->pc + prev_tb->size;
        const uint64_t cur_start = cur_tb->pc;

        const bool same_pc = (cur_start == prev_start);
        const bool inside_prev = (cur_start > prev_start && cur_start < prev_end);
        const bool sequential = (cur_start == prev_end);

        // Fast path: post-REP tail suppression
        if (sequential && ctx->executor->rep_artifacts.contains(prev_start))
            return;

        // Only now pay the XED decode cost
        if (same_pc || inside_prev)
        {
            const bool prev_ends_in_branch =
                ctx->executor->tb_ends_in_branch(uc, prev_tb->pc, prev_tb->size);

            if (!prev_ends_in_branch)
            {
                llvm::outs() << "REP artifact detected at 0x" << llvm::format_hex(prev_start, 16)
                             << " same_pc=" << same_pc
                             << " inside_prev=" << inside_prev
                             << " prev_ends_in_branch=" << prev_ends_in_branch << "\n";

                ctx->executor->rep_artifacts.insert(cur_start);
                return;
            }
        }

        // Otherwise, treat as genuine boundary / graph edge
        ctx->executor->genuine_edges.insert({prev_start, cur_start});
    }

    void UnicornExecutor::hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);

        const uint64_t prev = ctx->prev_block;

        const bool is_first = (prev == 0);
        const bool is_genuine_edge = ctx->executor->genuine_edges.contains({prev, address});

        if (!is_first && !is_genuine_edge)
        {
            const bool is_fallthrough =
                (ctx->prev_size != 0) && (address == prev + ctx->prev_size);

            if (ctx->prev_size != 0 &&
                !ctx->executor->rep_artifacts.contains(prev) && // optional extra guard
                ctx->executor->tb_ends_in_branch(uc, prev, (uint32_t)ctx->prev_size))
            {
                ctx->executor->genuine_edges.insert({prev, address});
                // accept (taken OR not-taken)
            }
            else
            {
                llvm::outs() << "Non-genuine edge detected: 0x" << llvm::format_hex(prev, 16)
                             << " -> 0x" << llvm::format_hex(address, 16)
                             << " is_fallthrough=" << is_fallthrough
                             << " prev_size=" << ctx->prev_size
                             << "\n";
                ctx->prev_block = address;
                ctx->prev_size = size;
                return;
            }
        }

        ctx->prev_block = address;
        ctx->prev_size = size;

        State state = unicorn_to_state(uc);

        if (ctx->executor->external_rvas.contains(address))
        {
            if (!ctx->state->context_ptr()->ext_call(ctx->state->context_ptr()->context, &state, address))
            {
                uc_emu_stop(uc);
                return;
            }

            // TODO: do we need to clear cache?
            // TODO: what about callee cleanup functs (e.g. stdcall)?
            // TODO: guard against jumping outside of module bounds?

            // Skip by jumping to [rsp]
            uint64_t rsp;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);

            uint64_t retaddr = ctx->state->memory().read64(rsp);
            uc_reg_write(uc, UC_X86_REG_RIP, &retaddr);
            ctx->executor->genuine_edges.insert({address, retaddr});

            // Adjust rsp to restore stack
            rsp += 8;
            uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
        }
        else
        {
            if (!ctx->state->context_ptr()->bb_entered(ctx->state->context_ptr()->context, &state, address - LOAD_BASE))
            {
                uc_emu_stop(uc);
                return;
            }
        }
    }

    bool UnicornExecutor::hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address,
                                           int size, int64_t value, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);

        // Calculate page boundaries (guard against overflow)
        uint64_t begin_page = address & ~0xFFFULL;
        uint64_t last_byte = (static_cast<uint64_t>(size) > 0 &&
                              address > UINT64_MAX - static_cast<uint64_t>(size - 1))
                                 ? UINT64_MAX
                                 : address + static_cast<uint64_t>(size - 1);
        uint64_t end_page = last_byte & ~0xFFFULL;

        // Map pages from paged_memory_state
        for (uint64_t page = begin_page;; page += 0x1000)
        {
            auto data = ctx->state->memory().map(page);
            if (!data.empty())
            {
                uc_err err = uc_mem_map(uc, page, data.size(), UC_PROT_ALL);
                if (err != UC_ERR_OK)
                    return false;

                err = uc_mem_write(uc, page, data.data(), data.size());
                if (err != UC_ERR_OK)
                    return false;
            }

            // Break BEFORE incrementing to avoid wraparound past UINT64_MAX
            if (page >= end_page)
                break;
        }

        return true;
    }

    void UnicornExecutor::hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                                        int size, int64_t value, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);
        auto *state = ctx->state;

        bool cont = false;

        // Read from paged_memory_state (which may sentinel-inject into its page data).
        // Capture the returned value and write it back into Unicorn's mapped memory so
        // the emulated CPU sees the same sentinel-injected value as the JIT executor.
        // This hook fires BEFORE Unicorn's actual hardware read, so the write-back takes
        // effect in time.
        uint64_t read_value = 0;
        switch (size)
        {
        case 1:
        {
            uint8_t val;
            cont = state->context_ptr()->read8(state->context_ptr()->context, address, val);
            read_value = val;
            break;
        }
        case 2:
        {
            uint16_t val;
            cont = state->context_ptr()->read16(state->context_ptr()->context, address, val);
            read_value = val;
            break;
        }
        case 4:
        {
            uint32_t val;
            cont = state->context_ptr()->read32(state->context_ptr()->context, address, val);
            read_value = val;
            break;
        }
        case 8:
        {
            uint64_t val;
            cont = state->context_ptr()->read64(state->context_ptr()->context, address, val);
            read_value = val;
            break;
        }
        }

        // Push the (possibly sentinel-patched) value into Unicorn's memory so the
        // emulated CPU reads the same bytes that paged_memory_state returned.
        // TODO: evaluate performance of this. If it's a problem, we can optimize by
        // only doing this for actual sentinel injections.
        uc_mem_write(uc, address, &read_value, size);

        if (!cont)
        {
            uc_emu_stop(uc);
        }
    }

    void UnicornExecutor::hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                                         int size, int64_t value, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);
        auto *state = ctx->state;

        bool cont = false;

        // Track memory access via verifier_context callbacks
        switch (size)
        {
        case 1:
            cont = state->context_ptr()->write8(state->context_ptr()->context, address, value);
            break;
        case 2:
            cont = state->context_ptr()->write16(state->context_ptr()->context, address, value);
            break;
        case 4:
            cont = state->context_ptr()->write32(state->context_ptr()->context, address, value);
            break;
        case 8:
            cont = state->context_ptr()->write64(state->context_ptr()->context, address, value);
            break;
        }

        if (!cont)
        {
            uc_emu_stop(uc);
        }
    }

    static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    {
        uint8_t code[15];
        uc_mem_read(uc, address, code, size);

        printf("%s\n", utils::insn_bytes_to_str(code, address).c_str());
    }

    bool UnicornExecutor::tb_ends_in_branch(uc_engine *uc, uint64_t pc, uint32_t size)
    {
        // Cache lookup: (tb_start, tb_size) is the stable key.
        // Keying by both avoids stale hits for the REP-split case where the same PC
        // appears with different TB sizes.
        auto key = std::make_pair(pc, size);
        if (auto it = tb_branch_cache.find(key); it != tb_branch_cache.end())
            return it->second;

        // XED state is constant for x86-64 long mode; initialize once.
        static const xed_state_t xed_state = [] {
            xed_state_t s;
            xed_state_init(&s, XED_MACHINE_MODE_LONG_64,
                           XED_ADDRESS_WIDTH_64b, XED_ADDRESS_WIDTH_64b);
            return s;
        }();

        // Read the full translation block from emulated memory.
        std::vector<uint8_t> buf(size);
        if (uc_mem_read(uc, pc, buf.data(), size) != UC_ERR_OK)
            return tb_branch_cache[key] = false;

        // Forward-walk instructions from the known-good TB start boundary.
        // x86 decoding is only reliable when started from a valid boundary; scanning
        // backward from the TB end can misidentify mid-instruction bytes as a valid
        // shorter instruction that happens to reach the end.
        uint32_t off = 0;
        while (off < size)
        {
            xed_decoded_inst_t xedd;
            xed_decoded_inst_zero(&xedd);
            xed_decoded_inst_set_mode(&xedd, xed_state.mmode, xed_state.stack_addr_width);

            xed_error_enum_t err = xed_decode(&xedd, buf.data() + off, size - off);
            if (err != XED_ERROR_NONE)
                break; // Decode failure at a forward boundary is a real error.

            uint32_t len = xed_decoded_inst_get_length(&xedd);
            if (len == 0)
                break; // Malformed; should not happen with well-formed code.

            if (off + len == size)
            {
                // This instruction ends exactly at the TB boundary — it is the last one.
                xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
                bool result = false;
                switch (cat)
                {
                case XED_CATEGORY_COND_BR:
                case XED_CATEGORY_UNCOND_BR:
                case XED_CATEGORY_CALL:
                case XED_CATEGORY_RET:
                case XED_CATEGORY_INTERRUPT:
                case XED_CATEGORY_SYSTEM:
                    result = true;
                    break;
                default:
                    break;
                }
                return tb_branch_cache[key] = result;
            }

            if (off + len > size)
                break; // Instruction extends past TB end — malformed TB.

            off += len;
        }

        // Decode did not reach the TB end — something is wrong with the TB.
        return tb_branch_cache[key] = false;
    }

    void UnicornExecutor::hint_external_rvas(const std::unordered_set<uint64_t> &rvas)
    {
        external_rvas.insert(rvas.begin(), rvas.end());
    }

    llvm::Expected<std::unique_ptr<UnicornExecutor>>
    UnicornExecutor::create(std::shared_ptr<LIEF::Binary> bin, std::unordered_set<uint64_t> ext_rvas, uint64_t entry_rva, Flags flags)
    {
        // Create executor (private constructor)
        auto executor = std::unique_ptr<UnicornExecutor>(
            new UnicornExecutor(bin, std::move(ext_rvas), entry_rva, flags));

        // Run setup
        if (auto err = executor->setup_impl())
        {
            return err;
        }

        return executor;
    }

    llvm::Error UnicornExecutor::setup_impl()
    {
        // Initialize XED decode tables exactly once across all UnicornExecutor instances.
        // xed_tables_init() is not documented as re-entrant; call_once guarantees safety.
        static std::once_flag xed_init_flag;
        std::call_once(xed_init_flag, xed_tables_init);

        // Create Unicorn engine
        uc_engine *uc_raw = nullptr;
        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc_raw);
        if (err != UC_ERR_OK)
        {
            return uc_error("uc_open", err);
        }
        uc_eng.reset(uc_raw);

        // Virtual TLB so we have 1:1 address mapping.
        // We don't care about arch limitations as we're using invalid memory anyway.
        uc_ctl_tlb_mode(uc_eng.get(), UC_TLB_VIRTUAL);

        // Save clean context
        uc_context *ctx_raw = nullptr;
        err = uc_context_alloc(uc_eng.get(), &ctx_raw);
        if (err != UC_ERR_OK)
        {
            return uc_error("uc_context_alloc", err);
        }
        clean_ctx.reset(ctx_raw);

        err = uc_context_save(uc_eng.get(), clean_ctx.get());
        if (err != UC_ERR_OK)
        {
            return uc_error("uc_context_save", err);
        }

        return llvm::Error::success();
    }

    llvm::Error UnicornExecutor::run_single_impl(verifier_state &state)
    {
        // Restore clean context
        uc_err err = uc_context_restore(uc_eng.get(), clean_ctx.get());
        if (err != UC_ERR_OK)
        {

            return llvm::make_error<llvm::StringError>(
                std::string("uc_context_restore failed: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        // Map initial State to Unicorn registers
        if (auto conv_err = state_to_unicorn(state.get_initial_state(), uc_eng.get()))
        {
            return llvm::make_error<llvm::StringError>(
                "Failed to set initial state",
                llvm::inconvertibleErrorCode());
        }

        // Register hooks
        uc_hook block_hook, edge_hook, mem_invalid_hook, mem_read_hook, mem_write_hook, code_hook;

        unicorn_ctx_t ctx = {
            .executor = this,
            .state = &state,
        };

        err = uc_hook_add(uc_eng.get(), &block_hook, UC_HOOK_BLOCK,
                          (void *)hook_block, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return llvm::make_error<llvm::StringError>(
                std::string("Failed to add block hook: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        err = uc_hook_add(uc_eng.get(), &edge_hook, UC_HOOK_EDGE_GENERATED,
                          (void *)hook_edge, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return llvm::make_error<llvm::StringError>(
                std::string("Failed to add edge hook: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        err = uc_hook_add(uc_eng.get(), &mem_invalid_hook,
                          UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                          (void *)hook_mem_invalid, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return llvm::make_error<llvm::StringError>(
                std::string("Failed to add mem_invalid hook: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        err = uc_hook_add(uc_eng.get(), &mem_read_hook, UC_HOOK_MEM_READ,
                          (void *)hook_mem_read, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return llvm::make_error<llvm::StringError>(
                std::string("Failed to add mem_read hook: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        err = uc_hook_add(uc_eng.get(), &mem_write_hook, UC_HOOK_MEM_WRITE,
                          (void *)hook_mem_write, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return llvm::make_error<llvm::StringError>(
                std::string("Failed to add mem_write hook: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        if (has_flag(flags, Flags::LOG_INSTRUCTIONS))
        {
            err = uc_hook_add(uc_eng.get(), &code_hook, UC_HOOK_CODE,
                              (void *)hook_code, nullptr, 1, 0);
            if (err != UC_ERR_OK)
            {
                return llvm::make_error<llvm::StringError>(
                    std::string("Failed to add code hook: ") + uc_strerror(err),
                    llvm::inconvertibleErrorCode());
            }
        }

        // Run emulation
        err = uc_emu_start(uc_eng.get(), state.get_initial_state().gpr.rip.qword, verifier_state::FINISH_SENTINEL, 0, 0);

        // Cleanup hooks
        uc_hook_del(uc_eng.get(), block_hook);
        uc_hook_del(uc_eng.get(), edge_hook);
        uc_hook_del(uc_eng.get(), mem_invalid_hook);
        uc_hook_del(uc_eng.get(), mem_read_hook);
        uc_hook_del(uc_eng.get(), mem_write_hook);

        if (has_flag(flags, Flags::LOG_INSTRUCTIONS))
        {
            uc_hook_del(uc_eng.get(), code_hook);
        }

        // Check emulation result
        if (err != UC_ERR_OK)
        {
            return llvm::make_error<llvm::StringError>(
                std::string("uc_emu_start failed: ") + uc_strerror(err),
                llvm::inconvertibleErrorCode());
        }

        // Read final state from Unicorn
        State final_state = unicorn_to_state(uc_eng.get());
        state.context_ptr()->final_reg_state = final_state;

        // TODO: Track instruction count
        return llvm::Error::success();
    }

} // namespace lifted::verification
