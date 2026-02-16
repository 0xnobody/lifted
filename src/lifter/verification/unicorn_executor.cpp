#include "unicorn_executor.hpp"

#include <sstream>

#include "nmd_assembly.h"

namespace lifted::verification
{
    struct unicorn_ctx_t
    {
        UnicornExecutor *executor;
        verifier_state *state;
    };

    // Helper to create Unicorn error messages
    static llvm::Error uc_error(const char *operation, uc_err err)
    {
        std::ostringstream msg;
        msg << operation << " failed: " << uc_strerror(err);
        return llvm::make_error<llvm::StringError>(msg.str(), llvm::inconvertibleErrorCode());
    }

    // Hook callbacks
    void UnicornExecutor::hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);

        if (ctx->executor->external_rvas.find(address) != ctx->executor->external_rvas.end())
        {
            ctx->state->context_ptr()->ext_call(ctx->state->context_ptr()->context, nullptr, address);

            // TODO: do we need to clear cache?
            // TODO: what about callee cleanup functs (e.g. stdcall)?
            // TODO: guard against jumping outside of module bounds?

            // Skip by jumping to [rsp]
            uint64_t rsp;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
            uc_reg_write(uc, UC_X86_REG_RIP, &rsp);

            // Adjust rsp to restore stack
            rsp += 8;
            uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
        }
        else
        {
            // Invoke verifier_state callback
            // Note: We don't have direct access to State* here in Unicorn,
            // so we pass nullptr for now (can be extended later if needed)
            ctx->state->context_ptr()->bb_entered(ctx->state->context_ptr()->context, nullptr, address);
        }
    }

    bool UnicornExecutor::hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address,
                                           int size, int64_t value, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);

        // Calculate page boundaries
        uint64_t begin_page = address & ~0xFFFULL;
        uint64_t end_page = (address + size - 1) & ~0xFFFULL;

        // Map pages from paged_memory_state
        for (uint64_t page = begin_page; page <= end_page; page += 0x1000)
        {
            auto data = ctx->state->memory().map(page);
            if (data.empty())
            {
                continue; // Skip unmapped pages
            }

            uc_err err = uc_mem_map(uc, page, data.size(), UC_PROT_ALL);
            if (err != UC_ERR_OK)
            {
                return false;
            }

            err = uc_mem_write(uc, page, data.data(), data.size());
            if (err != UC_ERR_OK)
            {
                return false;
            }
        }

        return true; // Successfully handled
    }

    void UnicornExecutor::hook_mem_read(uc_engine *uc, uc_mem_type type, uint64_t address,
                                        int size, int64_t value, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);
        auto *state = ctx->state;

        // Track memory access via verifier_context callbacks
        // Read appropriate size
        switch (size)
        {
        case 1:
            state->context_ptr()->read8(state->context_ptr()->context, address);
            break;
        case 2:
            state->context_ptr()->read16(state->context_ptr()->context, address);
            break;
        case 4:
            state->context_ptr()->read32(state->context_ptr()->context, address);
            break;
        case 8:
            state->context_ptr()->read64(state->context_ptr()->context, address);
            break;
        }
    }

    void UnicornExecutor::hook_mem_write(uc_engine *uc, uc_mem_type type, uint64_t address,
                                         int size, int64_t value, void *user_data)
    {
        auto *ctx = static_cast<unicorn_ctx_t *>(user_data);
        auto *state = ctx->state;

        // Track memory access via verifier_context callbacks
        switch (size)
        {
        case 1:
            state->context_ptr()->write8(state->context_ptr()->context, address, value);
            break;
        case 2:
            state->context_ptr()->write16(state->context_ptr()->context, address, value);
            break;
        case 4:
            state->context_ptr()->write32(state->context_ptr()->context, address, value);
            break;
        case 8:
            state->context_ptr()->write64(state->context_ptr()->context, address, value);
            break;
        }
    }

    static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    {
        uint8_t code[15];
        nmd_x86_instruction instruction;
        char formatted[128];

        // Read instruction bytes
        uc_mem_read(uc, address, code, size);

        // Decode and format
        if (nmd_x86_decode(code, size, &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_NONE))
        {
            nmd_x86_format(&instruction, formatted, address, NMD_X86_FORMAT_FLAGS_DEFAULT);
            printf("0x%" PRIx64 ":\t%s\n", address, formatted);
        }
        else
        {
            printf("0x%" PRIx64 ":\t[invalid]\n", address);
        }
    }

    llvm::Expected<std::unique_ptr<UnicornExecutor>>
    UnicornExecutor::create(std::shared_ptr<LIEF::Binary> bin, std::set<uint64_t> ext_rvas, uint64_t entry_rva)
    {
        // Create executor (private constructor)
        auto executor = std::unique_ptr<UnicornExecutor>(
            new UnicornExecutor(bin, ext_rvas, entry_rva));

        // Run setup
        if (auto err = executor->setup_impl())
        {
            return std::move(err);
        }

        return executor;
    }

    llvm::Error UnicornExecutor::setup_impl()
    {
        // Create Unicorn engine
        uc_engine *uc_raw = nullptr;
        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc_raw);
        if (err != UC_ERR_OK)
        {
            return uc_error("uc_open", err);
        }
        uc_eng.reset(uc_raw);

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

    ExecutionResult UnicornExecutor::run_single_impl(verifier_state &state)
    {
        // Restore clean context
        uc_err err = uc_context_restore(uc_eng.get(), clean_ctx.get());
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(
                StopReason::CRASH,
                std::string("uc_context_restore failed: ") + uc_strerror(err));
        }

        // Map initial State to Unicorn registers
        if (auto conv_err = state_to_unicorn(state.get_initial_state(), uc_eng.get()))
        {
            return ExecutionResult::error(
                StopReason::CRASH,
                "Failed to set initial state");
        }

        // Setup stack
        // State init_state_copy = state.get_initial_state();
        // if (auto stack_err = setup_unicorn_stack(uc_eng.get(), init_state_copy, STACK_MAGIC, FINISH_MAGIC))
        //{
        //    return ExecutionResult::error(
        //        StopReason::CRASH,
        //        "Failed to setup stack");
        //}

        // Update RSP in Unicorn
        // uint64_t rsp = init_state_copy.gpr.rsp.qword;
        // uc_reg_write(uc_eng.get(), UC_X86_REG_RSP, &rsp);

        // Register hooks
        uc_hook block_hook, mem_invalid_hook, mem_read_hook, mem_write_hook, code_hook;

        unicorn_ctx_t ctx = {
            .executor = this,
            .state = &state,
        };

        err = uc_hook_add(uc_eng.get(), &block_hook, UC_HOOK_BLOCK,
                          (void *)hook_block, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(StopReason::CRASH, "Failed to add block hook");
        }

        err = uc_hook_add(uc_eng.get(), &mem_invalid_hook,
                          UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                          (void *)hook_mem_invalid, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(StopReason::CRASH, "Failed to add mem_invalid hook");
        }

        err = uc_hook_add(uc_eng.get(), &mem_read_hook, UC_HOOK_MEM_READ,
                          (void *)hook_mem_read, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(StopReason::CRASH, "Failed to add mem_read hook");
        }

        err = uc_hook_add(uc_eng.get(), &mem_write_hook, UC_HOOK_MEM_WRITE,
                          (void *)hook_mem_write, &ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(StopReason::CRASH, "Failed to add mem_write hook");
        }

        err = uc_hook_add(uc_eng.get(), &code_hook, UC_HOOK_CODE,
                          (void *)hook_code, nullptr, 1, 0);
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(StopReason::CRASH, "Failed to add code hook");
        }

        // Run emulation
        uint64_t start_addr = LOAD_BASE + entry_rva;
        err = uc_emu_start(uc_eng.get(), start_addr, FINISH_MAGIC, 0, 0);

        // Cleanup hooks
        uc_hook_del(uc_eng.get(), block_hook);
        uc_hook_del(uc_eng.get(), mem_invalid_hook);
        uc_hook_del(uc_eng.get(), mem_read_hook);
        uc_hook_del(uc_eng.get(), mem_write_hook);
        uc_hook_del(uc_eng.get(), code_hook);

        // Check emulation result
        if (err != UC_ERR_OK)
        {
            return ExecutionResult::error(
                StopReason::CRASH,
                std::string("uc_emu_start failed: ") + uc_strerror(err));
        }

        // Read final state from Unicorn
        State final_state = unicorn_to_state(uc_eng.get());
        state.set_final_state(final_state);

        // TODO: Track instruction count
        return ExecutionResult::ok(0);
    }

} // namespace lifted::verification
