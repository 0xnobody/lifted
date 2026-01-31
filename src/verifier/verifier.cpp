#include "uc_raii.hpp"
#include "ext_call_policy.hpp"
#include <LIEF/LIEF.hpp>

#include <lifted/shared.hpp>

#include <vector>
#include <expected>
#include <random>
#include <set>

#define LOAD_BASE 0x7ffff7000000ULL

#define STACK_MAGIC 0x00007FFF00000000ULL
#define STACK_SIZE 0x00100000ULL // 1 MB - TODO: make configurable

#define FINISH_MAGIC 0x0000600000000000ULL

#define OR_RET_ERR(expr)      \
    do                        \
    {                         \
        uc_err err = (expr);  \
        if (err != UC_ERR_OK) \
            return err;       \
    } while (0)

uc_err get_reg_state(uc_engine *uc, reg_state_t &state)
{
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RAX, &state.rax));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RBX, &state.rbx));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RCX, &state.rcx));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RDX, &state.rdx));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RSI, &state.rsi));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RDI, &state.rdi));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RSP, &state.rsp));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_RBP, &state.rbp));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R8, &state.r8));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R9, &state.r9));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R10, &state.r10));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R11, &state.r11));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R12, &state.r12));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R13, &state.r13));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R14, &state.r14));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_R15, &state.r15));
    OR_RET_ERR(uc_reg_read(uc, UC_X86_REG_EFLAGS, &state.rflags));

    return UC_ERR_OK;
}

uc_err set_reg_state(uc_engine *uc, const reg_state_t &state)
{
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RAX, &state.rax));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RBX, &state.rbx));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RCX, &state.rcx));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RDX, &state.rdx));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RSI, &state.rsi));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RDI, &state.rdi));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RSP, &state.rsp));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_RBP, &state.rbp));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R8, &state.r8));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R9, &state.r9));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R10, &state.r10));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R11, &state.r11));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R12, &state.r12));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R13, &state.r13));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R14, &state.r14));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_R15, &state.r15));
    OR_RET_ERR(uc_reg_write(uc, UC_X86_REG_EFLAGS, &state.rflags));

    return UC_ERR_OK;
}

void setup_initial_regs(uint64_t seed, reg_state_t &state)
{
    // Initialize registers with deterministic pseudo-random values based on seed
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<uint64_t> dis;

    state.rax = dis(rng);
    state.rbx = dis(rng);
    state.rcx = dis(rng);
    state.rdx = dis(rng);
    state.rsi = dis(rng);
    state.rdi = dis(rng);
    state.rsp = 0; // will be set up separately
    state.rbp = dis(rng);
    state.r8 = dis(rng);
    state.r9 = dis(rng);
    state.r10 = dis(rng);
    state.r11 = dis(rng);
    state.r12 = dis(rng);
    state.r13 = dis(rng);
    state.r14 = dis(rng);
    state.r15 = dis(rng);
    state.rflags = 0x202; // default reserved bits
}

uc_err map_page(uc_engine *uc, paged_memory_state &mem, uint64_t page_addr)
{
    auto data = mem.map(page_addr);

    uc_err err = uc_mem_map(uc, page_addr, data.size(), UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to map page at 0x%lx (size: 0x%lx): %s", page_addr, data.size(), uc_strerror(err));
        return err;
    }

    // Write page content
    uc_err write_err = uc_mem_write(uc, page_addr, data.data(), data.size());
    if (write_err != UC_ERR_OK)
    {
        lifted::log_error("Failed to write page content at 0x%lx (size: 0x%lx): %s", page_addr, data.size(), uc_strerror(write_err));
    }
    else
    {
        lifted::log_debug("Mapped and wrote page at 0x%lx (size: 0x%lx)", page_addr, data.size());
    }

    return write_err;
}

uc_err setup_initial_stack(uc_engine *uc, reg_state_t &reg_state)
{
    // Stack grows downward: map [STACK_MAGIC - STACK_SIZE, STACK_MAGIC)
    // RSP points to return address at STACK_MAGIC - 8 (just below the top)
    uint64_t stack_base = STACK_MAGIC - STACK_SIZE;

    // Use uc_mem_map directly for zero-initialized memory (not random like other pages)
    uc_err err = uc_mem_map(uc, stack_base, STACK_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to map stack region at 0x%lx (size: 0x%lx): %s", stack_base, STACK_SIZE, uc_strerror(err));
        return err;
    }

    // Write return address (FINISH_MAGIC) at [STACK_MAGIC - 8]
    // RSP will point here, and ret instruction will pop this value
    // No need to track in mem_state since stack region is ignored in equivalence checking
    uint64_t ret_addr_location = STACK_MAGIC - 8;
    reg_state.rsp = ret_addr_location;

    uint64_t data = FINISH_MAGIC;
    return uc_mem_write(uc, ret_addr_location, &data, sizeof(data));
}

uc_err set_stack_state(uc_engine *uc, uint64_t stack_addr, size_t stack_size)
{
    // Map stack memory
    uc_err err = uc_mem_map(uc, stack_addr - stack_size, stack_size, UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to map stack at 0x%lx (size: 0x%lx): %s", stack_addr - stack_size, stack_size, uc_strerror(err));
        return err;
    }

    // Initialize RSP
    uint64_t rsp = stack_addr - 0x10; // leave some space
    err = uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to set RSP to 0x%lx: %s", rsp, uc_strerror(err));
        return err;
    }

    return UC_ERR_OK;
}

struct trace_result_t
{
    std::set<std::pair<uint64_t, uint64_t>> edges;
    std::set<uint64_t> basic_blocks;
    uint64_t last_bb_addr = 0;

    // External call tracking
    std::vector<ext_call_record> ext_call_seq;
    const ext_call_policy *ext_policy = nullptr;

    // Logical BB tracking for external calls that return to same BB
    // When set, suppress recording a new BB at this address
    std::optional<uint64_t> suppress_bb_at;

    paged_memory_state final_mem;

    reg_state_t initial_regs;
    reg_state_t final_regs;

    int stop_type;
    uint64_t finish_addr;

    // Memory ranges to exclude from tracking (e.g., stack)
    // These are managed separately and not tracked in paged_memory_state
    std::vector<mem_range_t> excluded_ranges;

    bool is_excluded(uint64_t addr) const
    {
        for (const auto &range : excluded_ranges)
        {
            if (addr >= range.start && addr < range.end)
            {
                return true;
            }
        }
        return false;
    }

    static trace_result_t from_baseline(const trace_result_t &baseline)
    {
        return trace_result_t{
            .edges = {},
            .basic_blocks = {},
            .last_bb_addr = 0,
            .ext_call_seq = {},
            .ext_policy = nullptr, // Policy set separately for test run
            .suppress_bb_at = std::nullopt,
            .final_mem = paged_memory_state::from_baseline(baseline.final_mem),
            .initial_regs = baseline.initial_regs,
            .final_regs = {},
            .stop_type = -1,
            .finish_addr = baseline.finish_addr,
            .excluded_ranges = baseline.excluded_ranges};
    }
};

// Handle external call: record it, adjust state, and redirect execution
static void handle_external_call(uc_engine *uc, trace_result_t *ctx, const ext_call_action &action)
{
    // Record the external call
    ctx->ext_call_seq.push_back({.target_rva = action.target_rva});

    // Adjust RSP
    if (action.rsp_adjustment != 0)
    {
        uint64_t rsp;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        rsp += action.rsp_adjustment;
        uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    }

    // Set up suppression if returning to same logical BB
    if (action.suppress_next_bb)
    {
        ctx->suppress_bb_at = action.resume_rip;
    }

    // Redirect to resume address
    uc_reg_write(uc, UC_X86_REG_RIP, &action.resume_rip);

    lifted::log_debug("External call to 0x%lx, resuming at 0x%lx (rsp adj: %ld)",
                      action.target_rva, action.resume_rip, action.rsp_adjustment);
}

// Callback for basic block execution
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    auto *ctx = static_cast<trace_result_t *>(user_data);

    lifted::log_debug("Entering BB at 0x%llx\n", address);

    if (address == ctx->finish_addr)
    {
        ctx->stop_type = 0;
        uc_emu_stop(uc);
        return;
    }

    // Check if we should suppress this BB (returning from same-BB external call)
    bool suppressed = false;
    if (ctx->suppress_bb_at.has_value() && ctx->suppress_bb_at.value() == address)
    {
        ctx->suppress_bb_at = std::nullopt;
        suppressed = true;
        lifted::log_debug("Suppressed BB at 0x%lx (same logical BB after ext call)", address);
    }

    // Check for external call via BB-level detection
    if (ctx->ext_policy && !ctx->ext_policy->use_instruction_hook())
    {
        auto action = ctx->ext_policy->check_block_entry(uc, address, ctx->last_bb_addr);
        if (action.has_value())
        {
            handle_external_call(uc, ctx, action.value());
            return; // Don't record this as a BB
        }
    }

    if (!suppressed)
    {
        // Record the basic block
        ctx->basic_blocks.insert(address);

        // Record edge from previous block if there was one
        if (ctx->last_bb_addr != 0)
        {
            ctx->edges.insert({ctx->last_bb_addr, address});
        }
    }

    ctx->last_bb_addr = address;
}

// Callback for memory access
static void hook_mem_access(uc_engine *uc, uc_mem_type type, uint64_t address,
                            int size, int64_t value, void *user_data)
{
    auto *ctx = static_cast<trace_result_t *>(user_data);

    // Skip tracking for excluded memory regions (e.g., stack)
    // These are managed separately and not part of program state comparison
    if (ctx->is_excluded(address))
    {
        return;
    }

    if (type == UC_MEM_READ)
    {
        // Read from paged memory state
        for (int i = 0; i < size; ++i)
        {
            ctx->final_mem.read8(address + i);
        }

        lifted::log_debug("Memory read at 0x%lx (size: %d)", address, size);
    }
    else if (type == UC_MEM_WRITE)
    {
        // For writes, read the actual bytes from Unicorn's memory and track them
        std::vector<uint8_t> buffer(size);
        uc_mem_read(uc, address, buffer.data(), size);

        for (int i = 0; i < size; ++i)
        {
            ctx->final_mem.write8(address + i, buffer[i]);
        }

        lifted::log_debug("Memory write at 0x%lx (size: %d)", address, size);
    }
}

// Callback for unmapped memory access (lazy allocation)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address,
                             int size, int64_t value, void *user_data)
{
    auto *ctx = static_cast<trace_result_t *>(user_data);

    uintptr_t begin_page = address & ~0xFFFULL;
    uintptr_t end_page = (address + size - 1) & ~0xFFFULL;

    if (begin_page == end_page)
    {
        // Single page access
        if (map_page(uc, ctx->final_mem, begin_page) != UC_ERR_OK)
        {
            lifted::log_error("Failed to lazy-map single page at 0x%lx", begin_page);
            return false;
        }
    }
    else
    {
        // Multi-page access
        for (uint64_t page = begin_page; page <= end_page; page += 0x1000)
        {
            if (map_page(uc, ctx->final_mem, page) != UC_ERR_OK)
            {
                lifted::log_error("Failed to lazy-map page at 0x%lx (multi-page access)", page);
                return false;
            }
        }
    }

    // Return true to indicate we handled the fault
    return true;
}

// Callback for interrupts/exceptions
static void hook_interrupt(uc_engine *uc, uint32_t intno, void *user_data)
{
    auto *ctx = static_cast<trace_result_t *>(user_data);

    ctx->stop_type = intno;

    lifted::log_debug("Interrupt/exception occurred: %u", intno);

    // Stop emulation on any unhandled interrupt/exception
    uc_emu_stop(uc);
}

// Callback for instruction-level external call detection
// Only used when ext_policy->use_instruction_hook() returns true
static void hook_code_ext_detect(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    auto *ctx = static_cast<trace_result_t *>(user_data);

    if (!ctx->ext_policy)
        return;

    // Read instruction bytes
    uint8_t insn[15];
    uc_mem_read(uc, address, insn, std::min(size, 15u));

    // Try to decode as control transfer
    auto xfer = decode_control_transfer(uc, address, insn, size);
    if (!xfer.has_value())
        return;

    // Ask policy if this is an external call
    auto action = ctx->ext_policy->check_transfer(uc, xfer.value());
    if (!action.has_value())
        return;

    // Handle the external call
    handle_external_call(uc, ctx, action.value());
}

uc_err record_run(uc_engine *uc,
                  trace_result_t &trace_ctx,
                  uint64_t func_addr,
                  uint64_t max_instructions = 0)
{
    using namespace lifted::uc;
    hook block_hook, mem_hook, mem_invalid_hook, interrupt_hook, code_hook;
    uc_err err;

    // Set up basic block hook
    err = hook_add(uc, block_hook, UC_HOOK_BLOCK, (void *)::hook_block, &trace_ctx, 1, 0);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to add basic block hook: %s", uc_strerror(err));
        return err;
    }

    // Set up instruction hook for external call detection (if policy requires it)
    if (trace_ctx.ext_policy && trace_ctx.ext_policy->use_instruction_hook())
    {
        err = hook_add(uc, code_hook, UC_HOOK_CODE, (void *)::hook_code_ext_detect, &trace_ctx, 1, 0);
        if (err != UC_ERR_OK)
        {
            lifted::log_error("Failed to add code hook for ext detection: %s", uc_strerror(err));
            return err;
        }
    }

    // Set up memory access hooks (read and write)
    err = hook_add(uc, mem_hook, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   (void *)::hook_mem_access, &trace_ctx, 1, 0);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to add memory access hook: %s", uc_strerror(err));
        return err;
    }

    // Set up unmapped memory hook for lazy allocation
    err = hook_add(uc, mem_invalid_hook,
                   UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                       UC_HOOK_MEM_FETCH_UNMAPPED,
                   (void *)::hook_mem_invalid, &trace_ctx, 1, 0);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to add unmapped memory hook: %s", uc_strerror(err));
        return err;
    }

    // Set up interrupt/exception hook to stop on unhandled exceptions
    err = hook_add(uc, interrupt_hook, UC_HOOK_INTR, (void *)::hook_interrupt, &trace_ctx, 1, 0);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to add interrupt hook: %s", uc_strerror(err));
        return err;
    }

    err = setup_initial_stack(uc, trace_ctx.initial_regs);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to setup initial stack: %s", uc_strerror(err));
        return err;
    }

    err = set_reg_state(uc, trace_ctx.initial_regs);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to set register state: %s", uc_strerror(err));
        return err;
    }

    // Start emulation - hooks cleaned up automatically on return
    return uc_emu_start(uc, func_addr, 0, 0, max_instructions);
}

std::expected<std::vector<trace_result_t>, uc_err> record_multiple(uint64_t func_addr, std::function<trace_result_t(int)> get_trace_result, int N, uint64_t base_addr = 0)
{
    using namespace lifted::uc;
    std::vector<trace_result_t> results;

    // Set up Unicorn engine
    engine uc;
    uc_err err = open(UC_ARCH_X86, UC_MODE_64, uc);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to open Unicorn engine: %s", uc_strerror(err));
        return std::unexpected(err);
    }

    err = uc_ctl_context_mode(uc.get(), UC_CTL_CONTEXT_MEMORY);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to set Unicorn context mode to memory: %s", uc_strerror(err));
        return std::unexpected(err);
    }

    // No upfront image mapping - all pages (image + dynamic) are lazily mapped
    // via hook_mem_invalid when first accessed

    context ctx;
    err = context_alloc(uc.get(), ctx);
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to allocate Unicorn context: %s", uc_strerror(err));
        return std::unexpected(err);
    }

    err = uc_context_save(uc.get(), ctx.get());
    if (err != UC_ERR_OK)
    {
        lifted::log_error("Failed to save initial Unicorn context: %s", uc_strerror(err));
        return std::unexpected(err);
    }

    for (int i = 0; i < N; i++)
    {
        // Restore context at start of each iteration
        err = uc_context_restore(uc.get(), ctx.get());
        if (err != UC_ERR_OK)
        {
            lifted::log_error("Failed to restore Unicorn context for test %d: %s", i, uc_strerror(err));
            return std::unexpected(err);
        }

        auto result = get_trace_result(i);

        // Emulate
        err = record_run(uc.get(), result, func_addr + base_addr);
        if (err != UC_ERR_OK)
        {
            lifted::log_error("Failed to run emulation for test %d at 0x%lx: %s", i, func_addr + base_addr, uc_strerror(err));
            return std::unexpected(err);
        }

        err = get_reg_state(uc.get(), result.final_regs);
        if (err != UC_ERR_OK)
        {
            lifted::log_error("Failed to get final register state for test %d: %s", i, uc_strerror(err));
            return std::unexpected(err);
        }

        results.push_back(result);
    }

    return results;
}

int main(int argc, char **argv)
{
    const char *binary_path = "/home/atlas/lifted/build/src/evaluation/synthetic/libeval-loop-bounded.so";             // argv[1];
    const char *obf_binary_path = "/home/atlas/lifted/build/src/evaluation/synthetic/libeval-loop-bounded-polaris.so"; // argv[1];

    // Parse binaries and convert to shared_ptr for shared ownership in paged_memory_state
    std::shared_ptr<LIEF::Binary> binary{LIEF::Parser::parse(binary_path).release()};
    std::shared_ptr<LIEF::Binary> obf_binary{LIEF::Parser::parse(obf_binary_path).release()};

    if (!binary)
    {
        lifted::log_error("Failed to parse binary: %s", binary_path);
        return EXIT_FAILURE;
    }

    if (!obf_binary)
    {
        lifted::log_error("Failed to parse obfuscated binary: %s", obf_binary_path);
        return EXIT_FAILURE;
    }

    uint64_t func_addr = 0x1100;

    std::mt19937_64 rng(123);
    std::uniform_int_distribution<uint64_t> seed_dis(0, UINT64_MAX);

    // Generate a master seed for this verification run
    uint64_t master_seed = seed_dis(rng);

    auto rand_trace_result = [&](int run)
    {
        trace_result_t result = {
            .edges = {},
            .basic_blocks = {},
            .last_bb_addr = 0,
            .ext_call_seq = {},
            .ext_policy = nullptr, // No external call handling for now
            .suppress_bb_at = std::nullopt,
            .final_mem = paged_memory_state::init(master_seed, binary, LOAD_BASE),
            .initial_regs = {},
            .final_regs = {},
            .stop_type = -1,
            .finish_addr = FINISH_MAGIC,
            .excluded_ranges = {{STACK_MAGIC - STACK_SIZE, STACK_MAGIC}},
        };

        setup_initial_regs(seed_dis(rng), result.initial_regs);

        return result;
    };

    auto initial_results = record_multiple(func_addr, rand_trace_result, 1, LOAD_BASE);

    auto trace_result_from_baseline = [&](int run)
    {
        auto baseline_result = trace_result_t::from_baseline((*initial_results)[run]);
        // Replace memory state with one loaded from obfuscated binary (same master seed)
        baseline_result.final_mem = paged_memory_state::from_baseline(
            (*initial_results)[run].final_mem, obf_binary, LOAD_BASE);
        return baseline_result;
    };

    auto subsequent_results = record_multiple(func_addr, trace_result_from_baseline, 1, LOAD_BASE);

    // Verify equivalence
    if (!initial_results || !subsequent_results)
    {
        lifted::log_error("Failed to record traces");
        return EXIT_FAILURE;
    }

    bool all_equivalent = true;
    for (size_t i = 0; i < initial_results->size(); ++i)
    {
        const auto &baseline = (*initial_results)[i];
        const auto &test = (*subsequent_results)[i];

        // Define ignored memory ranges (e.g., stack region)
        mem_range_t stack_range = {STACK_MAGIC - STACK_SIZE, STACK_MAGIC};
        std::array<mem_range_t, 1> ignored = {stack_range};

        // Compare memory states
        bool mem_equiv = baseline.final_mem.compare(test.final_mem, ignored);

        // Compare return values (RAX, RDX for System V ABI)
        bool ret_equiv = baseline.final_regs.compare_return_value(test.final_regs);

        // Compare callee-saved registers (should be preserved)
        bool callee_saved_equiv = baseline.final_regs.compare_systemv_nonvolatile(test.final_regs);

        // Compare external call sequences
        bool ext_equiv = (baseline.ext_call_seq.size() == test.ext_call_seq.size());
        if (ext_equiv)
        {
            for (size_t j = 0; j < baseline.ext_call_seq.size(); ++j)
            {
                if (baseline.ext_call_seq[j].target_rva != test.ext_call_seq[j].target_rva)
                {
                    ext_equiv = false;
                    break;
                }
                // Future: compare arguments here
            }
        }

        if (!mem_equiv || !ret_equiv || !ext_equiv)
        {
            lifted::log_error("Test %zu: NOT EQUIVALENT (mem=%d, ret=%d, callee_saved=%d, ext=%d)",
                              i, mem_equiv, ret_equiv, callee_saved_equiv, ext_equiv);
            all_equivalent = false;

            // Print stats for debugging
            auto baseline_stats = baseline.final_mem.get_stats();
            auto test_stats = test.final_mem.get_stats();
            lifted::log_debug("  Baseline: %zu pages, %zu written bytes, %zu ext calls",
                              baseline_stats.total_pages, baseline_stats.total_bytes_written,
                              baseline.ext_call_seq.size());
            lifted::log_debug("  Test:     %zu pages, %zu written bytes, %zu ext calls",
                              test_stats.total_pages, test_stats.total_bytes_written,
                              test.ext_call_seq.size());
        }
        else
        {
            lifted::log_info("Test %zu: EQUIVALENT", i);
        }
    }

    return all_equivalent ? EXIT_SUCCESS : EXIT_FAILURE;
}
