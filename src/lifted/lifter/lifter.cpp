#include "lifter.hpp"

#include "helper_state_annotations.hpp"

#include "../abi/abi_utils.hpp"
#include "../abi/function_state_attrs.hpp"
#include "../compat/lief_compat.hpp"
#include "../helpers.hpp"
#include "../opt.hpp"
#include "lifter_utils.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <glog/logging.h>

#include <chrono>
#include <sstream>
#include <stack>

namespace lifted::lifter
{

using Clock = std::chrono::steady_clock;
using Ms = std::chrono::duration<double, std::milli>;

static double elapsed_ms(Clock::time_point start)
{
    return Ms(Clock::now() - start).count();
}

static llvm::Error annotate_lifted_function(llvm::Function &F, annotation_id_t annotation_id)
{
    if (auto err = abi::set_state_form(F, abi::state_form_t::folded))
        return err;
    return abi::set_annotation_id(F, annotation_id);
}

static llvm::Error emit_opaque_call_stub_body(llvm::Function &stub,
                                              llvm::Function &opaque_target,
                                              const abi::CallingConvention &cc)
{
    auto *module = stub.getParent();
    auto *read_mem64 = module->getFunction("__remill_read_memory_64");
    auto *store_rip = module->getFunction("__store_rip");
    if (!read_mem64 || !store_rip)
    {
        return llvm::make_error<llvm::StringError>(
            "missing __remill_read_memory_64 or __store_rip while building callee stub",
            llvm::inconvertibleErrorCode());
    }

    auto *state_ptr = remill::NthArgument(&stub, remill::kStatePointerArgNum);
    auto *pc = remill::LoadProgramCounterArg(&stub);
    auto *memory = remill::LoadMemoryPointerArg(&stub);

    auto *entry = llvm::BasicBlock::Create(module->getContext(), "entry", &stub);
    llvm::IRBuilder<> ir(entry);

    llvm::Value *saved_rsp = abi::ExtractRegister(ir, abi::ABIRegister::RSP, state_ptr);
    llvm::Value *retaddr = ir.CreateCall(read_mem64, {memory, saved_rsp}, "retaddr");
    std::vector<std::pair<abi::ABIRegister, llvm::Value *>> saved_nonvolatile_registers;
    saved_nonvolatile_registers.reserve(cc.getNonVolatileRegisters().size());
    for (auto reg : cc.getNonVolatileRegisters())
    {
        saved_nonvolatile_registers.emplace_back(reg, abi::ExtractRegister(ir, reg, state_ptr));
    }

    ir.CreateCall(&opaque_target, {state_ptr, pc, memory});

    ir.CreateCall(store_rip, {state_ptr, retaddr});
    for (const auto &[reg, saved_value] : saved_nonvolatile_registers)
        abi::StoreRegister(ir, reg, state_ptr, saved_value);
    abi::StoreRegister(
        ir, abi::ABIRegister::RSP, state_ptr,
        ir.CreateAdd(saved_rsp, llvm::ConstantInt::get(saved_rsp->getType(), 8)));
    ir.CreateRet(memory);
    return llvm::Error::success();
}

// ── Constructor ────────────────────────────────────────────────────────────

Lifter::Lifter(const remill::Arch *arch,
               BinaryContext *bin_ctx,
               LifterCallbacks *callbacks,
               annotation_id_t core_annotation_id,
               std::unique_ptr<llvm::Module> work_module)
    : arch_(arch),
      intrinsics_(arch->GetInstrinsicTable()),
      bin_ctx_(bin_ctx),
      callbacks_(callbacks),
      work_module_(std::move(work_module)),
      bb_cache_module_(std::make_unique<llvm::Module>(
          "bb_cache", work_module_->getContext())),
      core_annotation_id_(core_annotation_id)
{
}

/*static*/ llvm::Expected<Lifter>
Lifter::create(const remill::Arch *arch,
               BinaryContext &bin_ctx,
               LifterCallbacks *callbacks)
{
    auto work_module = remill::LoadArchSemantics(arch);
    if (auto err = helpers::link_state_utils(work_module.get()))
        return std::move(err);
    if (auto err = helpers::link_lifting_helpers(work_module.get()))
        return std::move(err);

    auto core_annotation_id =
        bin_ctx.get_or_create_builtin_annotation(builtin_annotation_kind_t::lifted_core_all_registers);
    if (auto err = annotate_linked_state_helpers(*work_module, bin_ctx, core_annotation_id))
        return std::move(err);

    return Lifter(arch, &bin_ctx, callbacks, core_annotation_id, std::move(work_module));
}

// ── Binary helpers ──────────────────────────────────────────────────────────

bool Lifter::is_executable(uint64_t addr) const
{
    auto fmt = bin_ctx_->binary().format();
    switch (fmt)
    {
    case LIEF::EXE_FORMATS::FORMAT_ELF:
    {
        const auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(&bin_ctx_->binary());
        const auto *section = elf->section_from_virtual_address(addr);
        if (!section)
            return false;
        return section->has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
    }
    case LIEF::EXE_FORMATS::FORMAT_PE:
    {
        uint64_t rva = addr - bin_ctx_->binary().imagebase();
        const auto *pe = dynamic_cast<const LIEF::PE::Binary *>(&bin_ctx_->binary());
        const auto *section = pe->section_from_rva(rva);
        if (!section)
            return false;
        return section->has_characteristic(
            LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
    }
    case LIEF::EXE_FORMATS::FORMAT_MACHO:
    {
        const auto *macho = dynamic_cast<const LIEF::MachO::Binary *>(&bin_ctx_->binary());
        const auto *section = macho->section_from_virtual_address(addr);
        if (!section)
            return false;
        return section->has(
            LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS);
    }
    default:
        // Unsupported format; treat as non-executable rather than crash.
        DLOG(WARNING) << "Lifter::is_executable: unsupported LIEF format "
                      << static_cast<int>(fmt);
        return false;
    }
}

bool Lifter::try_read_byte(uint64_t addr, uint8_t *byte) const
{
    if (!is_executable(addr))
        return false;
    auto content = bin_ctx_->binary().get_content_from_virtual_address(addr, 1);
    if (content.empty())
    {
        std::cerr << "Warning: reached end of section at 0x" << std::hex << addr
                  << std::dec << "\n";
        return false;
    }
    if (byte)
        *byte = content[0];
    return true;
}

std::string Lifter::read_instruction_bytes(uint64_t addr) const
{
    auto max_bytes = arch_->MaxInstructionSize(arch_->CreateInitialContext());
    std::string bytes;
    for (size_t i = 0; i < max_bytes; ++i)
    {
        uint64_t byte_addr = addr + i;
        if (byte_addr < addr) // overflow
            break;
        uint8_t b = 0;
        if (!try_read_byte(byte_addr, &b))
            break;
        bytes.push_back(static_cast<char>(b));
    }
    return bytes;
}

// ── BB cache helpers ────────────────────────────────────────────────────────

std::optional<bb_id_t> Lifter::find_next_explored_real_bb(bb_id_t curr_id) const
{
    // explored_ is a std::map ordered by key (= start address).
    // upper_bound gives the first entry with ID > curr_id in O(log n).
    auto it = explored_.upper_bound(curr_id);
    while (it != explored_.end())
    {
        if (it->second.type == lifted_bb_t::Type::REAL)
            return it->first;
        ++it;
    }
    return std::nullopt;
}
// ── Callee stubs ────────────────────────────────────────────────────────────

llvm::Expected<llvm::Function *> Lifter::get_or_create_callee_stub(llvm::Module *M,
                                                                   annotation_id_t annotation_id,
                                                                   bool recursive)
{
    auto annotation = bin_ctx_->get_by_id(annotation_id);

    std::string key = !annotation->name.empty()
                          ? annotation->name
                          : (recursive ? "recursive_" : "indirect_") +
                                std::to_string(next_indirect_stub_id_++);

    auto it = callee_stubs_.find(key);
    if (it != callee_stubs_.end())
    {
        if (auto *existing = M->getFunction(it->second.stub_func_name))
            return existing;
    }

    llvm::Function *opaque_target = nullptr;
    std::string stub_name;
    std::string ext_call_decl_name;

    if (recursive)
    {
        opaque_target = M->getFunction("__lifted_recursive_call");
        if (!opaque_target)
        {
            return llvm::make_error<llvm::StringError>(
                "missing __lifted_recursive_call declaration",
                llvm::inconvertibleErrorCode());
        }
        stub_name = "__lifted_recursive_call_" + key + "_stub";
    }
    else
    {
        auto *shared_ext_call = M->getFunction("__lifted_ext_call");
        if (!shared_ext_call)
        {
            return llvm::make_error<llvm::StringError>(
                "missing __lifted_ext_call declaration",
                llvm::inconvertibleErrorCode());
        }

        ext_call_decl_name = "__lifted_ext_call_" + key;
        opaque_target = M->getFunction(ext_call_decl_name);
        if (!opaque_target)
        {
            opaque_target = llvm::Function::Create(
                shared_ext_call->getFunctionType(),
                llvm::GlobalValue::ExternalLinkage,
                ext_call_decl_name, M);
            if (auto err = annotate_lifted_function(*opaque_target, annotation->id))
                return std::move(err);
        }
        stub_name = ext_call_decl_name + "_stub";
    }

    if (auto *existing = M->getFunction(stub_name))
        return existing;

    auto *stub = llvm::Function::Create(
        opaque_target->getFunctionType(), llvm::GlobalValue::InternalLinkage, stub_name, M);
    stub->addFnAttr(llvm::Attribute::AlwaysInline);
    if (auto err = annotate_lifted_function(*stub, annotation->id))
        return std::move(err);
    if (auto err = emit_opaque_call_stub_body(*stub, *opaque_target, *annotation->cc))
        return std::move(err);

    callee_stubs_[key] = callee_stub_entry_t{
        stub->getName().str(),
        ext_call_decl_name,
        annotation->id};
    return stub;
}

// ── Synthetic BB ────────────────────────────────────────────────────────────

llvm::Expected<lifted_bb_t> Lifter::create_synthetic_bb(
    bb_id_t id,
    const synthetic_block_info_t &synth_info)
{
    std::stringstream ss;
    ss << "BB_" << std::hex << id;
    switch (synth_info.type)
    {
    case synthetic_block_info_t::Type::EXTERNAL:
        ss << "_ext";
        break;
    case synthetic_block_info_t::Type::RECURSIVE:
        ss << "_recur";
        break;
    case synthetic_block_info_t::Type::INDIRECT:
        ss << "_indr";
        break;
    }
    auto *F = arch_->DeclareLiftedFunction(ss.str(), work_module_.get());
    arch_->InitializeEmptyLiftedFunction(F);

    const bool recursive = synth_info.type == synthetic_block_info_t::Type::RECURSIVE;
    if (auto err = annotate_lifted_function(*F, synth_info.annotation_id))
        return std::move(err);

    auto *state_ptr = remill::NthArgument(F, remill::kStatePointerArgNum);
    auto *pc = remill::LoadProgramCounterArg(F);
    auto *mem = remill::LoadMemoryPointerArg(F);

    llvm::IRBuilder<> ir(&F->getEntryBlock());
    auto stub_or = get_or_create_callee_stub(work_module_.get(), synth_info.annotation_id, recursive);
    if (!stub_or)
        return stub_or.takeError();
    ir.CreateRet(ir.CreateCall(*stub_or, {state_ptr, pc, mem}));

    return lifted_bb_t{
        .type = lifted_bb_t::Type::SYNTHETIC,
        .id = id,
        .func_name = F->getName().str(),
        .rva_range = std::nullopt,
        .terminating_category = std::nullopt,
        .static_target_rva = std::nullopt,
        .static_continuation_rva = std::nullopt};
}

// ── lift_bb ─────────────────────────────────────────────────────────────────

llvm::Expected<lifted_bb_t> Lifter::lift_bb(uintptr_t addr,
                                            annotation_id_t annotation_id,
                                            std::optional<uintptr_t> stop_at)
{
    auto &ctx_ref = *work_module_;
    auto &Context = ctx_ref.getContext();

    std::stringstream ss;
    ss << "BB_" << std::hex << addr;

    auto *F = arch_->DeclareLiftedFunction(ss.str(), work_module_.get());
    arch_->InitializeEmptyLiftedFunction(F);
    if (auto err = annotate_lifted_function(*F, annotation_id))
        return std::move(err);

    std::stack<uint64_t> inst_worklist;
    std::map<uint64_t, llvm::BasicBlock *> blocks;

    inst_worklist.push(addr);

    auto get_or_create_block = [&](uint64_t address) -> llvm::BasicBlock *
    {
        auto &blk = blocks[address];
        if (!blk)
            blk = llvm::BasicBlock::Create(Context, "", F);
        return blk;
    };

    auto get_or_create_next_block = [&]() -> llvm::BasicBlock *
    {
        remill::Instruction inst_next;
        // Just push next_pc to the worklist; the current `inst` is captured
        // in the outer loop below.
        (void)inst_next;
        // We'll handle this inside the decode loop below.
        return nullptr; // sentinel; replaced below
    };
    (void)get_or_create_next_block; // suppress unused warning

    auto *state_ptr = remill::NthArgument(F, remill::kStatePointerArgNum);

    if (auto *entry_block = &F->front())
    {
        auto *pc = remill::LoadProgramCounterArg(F);
        auto [next_pc_ref, next_pc_ref_type] =
            arch_->DefaultLifter(*intrinsics_)
                ->LoadRegAddress(entry_block, state_ptr, remill::kNextPCVariableName);
        (void)new llvm::StoreInst(pc, next_pc_ref, entry_block);
        llvm::BranchInst::Create(get_or_create_block(addr), entry_block);
    }

    remill::Instruction inst;
    uint64_t block_end = addr;
    std::optional<uint64_t> static_target_rva;
    std::optional<uint64_t> static_continuation_rva;

    while (!inst_worklist.empty())
    {
        const auto inst_addr = inst_worklist.top();
        inst_worklist.pop();

        auto *block = get_or_create_block(inst_addr);

        // Stop boundary check.
        if (stop_at && inst_addr >= *stop_at)
        {
            if (inst_addr > *stop_at)
                DLOG(WARNING) << "lift_bb: stop address not aligned with instruction "
                                 "boundary at 0x"
                              << std::hex << inst_addr;

            auto pc_ref = const_cast<llvm::Value *>(remill::LoadProgramCounterRef(block));
            auto next_pc_ref = const_cast<llvm::Value *>(remill::LoadNextProgramCounterRef(block));
            auto *memory = remill::NthArgument(F, remill::kMemoryPointerArgNum);
            llvm::IRBuilder<> ir(block);
            ir.CreateStore(ir.CreateLoad(arch_->AddressType(), next_pc_ref), pc_ref);
            ir.CreateRet(memory);

            // The stop_at boundary actually fired → truncated.
            return lifted_bb_t{
                .type = lifted_bb_t::Type::REAL,
                .id = addr,
                .func_name = F->getName().str(),
                .rva_range = llvm::AddressRange{addr, inst_addr},
                .terminating_category = inst.category,
                .static_target_rva = inst.next_pc,
                .static_continuation_rva = std::nullopt,
                .was_truncated_by_stop = true};
        }

        auto inst_bytes = read_instruction_bytes(inst_addr);
        inst.Reset();
        std::ignore = arch_->DecodeInstruction(
            inst_addr, inst_bytes, inst, arch_->CreateInitialContext());

        auto lift_status =
            inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr);
        if (remill::kLiftedInstruction != lift_status)
        {
            remill::AddTerminatingTailCall(block, intrinsics_->error, *intrinsics_);
            continue;
        }

        block_end = inst.next_pc;

        // Wire blocks together.
        switch (inst.category)
        {
        case remill::Instruction::kCategoryAsyncHyperCall:
        case remill::Instruction::kCategoryConditionalAsyncHyperCall:
        case remill::Instruction::kCategoryConditionalDirectFunctionCall:
        case remill::Instruction::kCategoryConditionalIndirectFunctionCall:
            DLOG(WARNING) << "lift_bb: unsupported instruction category "
                          << inst.category << " at 0x" << std::hex << inst_addr;
            [[fallthrough]];
        case remill::Instruction::kCategoryInvalid:
        case remill::Instruction::kCategoryError:
            remill::AddTerminatingTailCall(block, intrinsics_->error, *intrinsics_);
            break;

        case remill::Instruction::kCategoryNormal:
        case remill::Instruction::kCategoryNoOp:
            inst_worklist.push(inst.next_pc);
            llvm::BranchInst::Create(get_or_create_block(inst.next_pc), block);
            break;

        case remill::Instruction::kCategoryConditionalBranch:
        case remill::Instruction::kCategoryDirectJump:
        {
            // Store NEXT_PC into PC so callers can read the computed target.
            auto pc_ref = const_cast<llvm::Value *>(remill::LoadProgramCounterRef(block));
            auto next_pc_ref = const_cast<llvm::Value *>(remill::LoadNextProgramCounterRef(block));
            llvm::IRBuilder<> ir(block);
            ir.CreateStore(ir.CreateLoad(arch_->AddressType(), next_pc_ref), pc_ref);
            [[fallthrough]];
        }
        case remill::Instruction::kCategoryIndirectJump:
        case remill::Instruction::kCategoryConditionalIndirectJump:
        case remill::Instruction::kCategoryDirectFunctionCall:
        case remill::Instruction::kCategoryIndirectFunctionCall:
        case remill::Instruction::kCategoryFunctionReturn:
        default:
        {
            auto *memory = remill::LoadMemoryPointer(block, *intrinsics_);
            llvm::IRBuilder<> ir(block);
            ir.CreateRet(memory);
            break;
        }
        }
    }

    switch (inst.category)
    {
    case remill::Instruction::kCategoryNormal:
        static_target_rva = inst.next_pc;
        break;
    case remill::Instruction::kCategoryDirectJump:
        static_target_rva = inst.branch_taken_pc;
        break;
    case remill::Instruction::kCategoryConditionalBranch:
        static_target_rva = inst.branch_taken_pc;
        static_continuation_rva =
            inst.branch_not_taken_pc ? inst.branch_not_taken_pc : inst.next_pc;
        break;
    case remill::Instruction::kCategoryDirectFunctionCall:
        static_target_rva = inst.branch_taken_pc;
        static_continuation_rva =
            inst.branch_not_taken_pc ? inst.branch_not_taken_pc : inst.next_pc;
        break;
    case remill::Instruction::kCategoryIndirectFunctionCall:
        static_continuation_rva = inst.next_pc;
        break;
    default:
        break;
    }

    return lifted_bb_t{
        .type = lifted_bb_t::Type::REAL,
        .id = addr,
        .func_name = F->getName().str(),
        .rva_range = llvm::AddressRange{addr, block_end},
        .terminating_category = inst.category,
        .static_target_rva = static_target_rva,
        .static_continuation_rva = static_continuation_rva};
}

// ── lift() ──────────────────────────────────────────────────────────────────

llvm::Expected<lift_result_t> Lifter::lift(uint64_t entry_rva,
                                           annotation_id_t entry_annotation_id,
                                           lift_config_t config)
{
    auto total_start = Clock::now();
    lift_stats_t stats;

    lift_context_t ctx;
    ctx.entry_rva = entry_rva;
    ctx.entry_annotation_id = entry_annotation_id;
    ctx.worklist.push_back(static_cast<bb_id_t>(entry_rva));

    while (!ctx.worklist.empty() || !ctx.reprove.empty())
    {
        if (ctx.worklist.empty())
        {
            for (bb_id_t id : ctx.reprove)
                ctx.worklist.push_back(id);
            ctx.reprove.clear();
        }

        bb_id_t curr_id = ctx.worklist.front();
        ctx.worklist.pop_front();

        if (!callbacks_->should_continue_exploration(curr_id, ctx))
            continue;

        // ── Block splitting ─────────────────────────────────────────────

        if (!is_synthetic(curr_id))
        {
            uint64_t current_addr = static_cast<uint64_t>(curr_id);

            // Find any REAL block that contains current_addr as a mid-block address.
            auto owning_it = std::find_if(
                explored_.begin(), explored_.end(),
                [&](const auto &pair)
                {
                    const auto &bb = pair.second;
                    return bb.type == lifted_bb_t::Type::REAL &&
                           current_addr >= bb.rva_range->start() &&
                           current_addr < bb.rva_range->end();
                });

            if (owning_it != explored_.end())
            {
                auto &orig = owning_it->second;
                if (orig.rva_range->start() != current_addr)
                {
                    // Split: [orig.start, orig.end) → [orig.start, current_addr) +
                    //        [current_addr, orig.end)
                    DLOG(INFO) << "lift: splitting block [0x"
                               << std::hex << orig.rva_range->start()
                               << ", 0x" << orig.rva_range->end()
                               << ") at 0x" << current_addr;

                    bb_id_t orig_id = orig.id;
                    const auto &orig_name = orig.func_name;

                    // Remove old block.
                    explored_.erase(orig_id);
                    if (auto *old_fn = work_module_->getFunction(orig_name))
                        old_fn->eraseFromParent();
                    if (auto *old_fn = bb_cache_module_->getFunction(orig_name))
                        old_fn->eraseFromParent();

                    // Lift both halves.
                    auto lift_start = Clock::now();
                    auto bb_start_or = lift_bb(
                        orig.rva_range->start(), core_annotation_id_, current_addr);
                    if (!bb_start_or)
                        return bb_start_or.takeError();
                    auto bb_end_or = lift_bb(current_addr, core_annotation_id_);
                    if (!bb_end_or)
                        return bb_end_or.takeError();
                    lifted_bb_t bb_start = *bb_start_or;
                    lifted_bb_t bb_end = *bb_end_or;
                    stats.lift_time_ms += elapsed_ms(lift_start);
                    stats.bbs_lifted += 2;

                    auto *fn_start = work_module_->getFunction(bb_start.func_name);
                    auto *fn_end = work_module_->getFunction(bb_end.func_name);

                    callbacks_->process_bb(bb_start, fn_start);
                    remill::MoveFunctionIntoModule(fn_start, bb_cache_module_.get());
                    explored_[bb_start.id] = bb_start;

                    callbacks_->process_bb(bb_end, fn_end);
                    remill::MoveFunctionIntoModule(fn_end, bb_cache_module_.get());
                    explored_[bb_end.id] = bb_end;

                    // Redirect outgoing edges of original → bb_end.
                    std::vector<edge_t> to_remove, to_add;
                    for (const auto &e : ctx.edges)
                        if (e.source == orig_id)
                        {
                            to_remove.push_back(e);
                            to_add.push_back(edge_t{bb_end.id, e.dest, e.type});
                        }
                    for (const auto &e : to_remove)
                        ctx.edges.erase(e);
                    for (const auto &e : to_add)
                        ctx.edges.insert(e);
                    ctx.remap_synthetic_sources(orig_id, bb_end.id);

                    // Fallthrough edge from bb_start → bb_end.
                    ctx.edges.insert(edge_t{bb_start.id, bb_end.id,
                                            edge_t::Type::FALLTHROUGH});
                    callbacks_->on_block_split(orig_id, bb_start.id, bb_end.id);

                    // bb_start has a new outgoing edge → reprove.
                    // ctx.reprove.insert(bb_start.id);
                }
            }
        }

        DLOG(INFO) << "lift: analysing 0x" << std::hex << curr_id;

        // ── Lift or retrieve from cache ─────────────────────────────────

        lifted_bb_t bb;
        std::optional<bb_id_t> maybe_stop;

        if (!explored_.count(curr_id))
        {
            auto lift_start = Clock::now();
            if (is_synthetic(curr_id))
            {
                const auto &synth_info = ctx.synthetic_blocks.at(curr_id);
                auto bb_or = create_synthetic_bb(curr_id, synth_info);
                if (!bb_or)
                    return bb_or.takeError();
                bb = *bb_or;
            }
            else
            {
                maybe_stop = find_next_explored_real_bb(curr_id);
                auto bb_or = lift_bb(curr_id, core_annotation_id_, maybe_stop);
                if (!bb_or)
                    return bb_or.takeError();
                bb = *bb_or;
            }
            stats.lift_time_ms += elapsed_ms(lift_start);
            stats.bbs_lifted++;

            auto *func = work_module_->getFunction(bb.func_name);
            callbacks_->process_bb(bb, func);

            remill::MoveFunctionIntoModule(func, bb_cache_module_.get());
            explored_.insert({curr_id, bb});

            // If truncated by a prior block, add fallthrough and reprove.
            if (!is_synthetic(curr_id) && bb.was_truncated_by_stop)
            {
                DLOG(INFO) << "lift: fallthrough 0x" << std::hex << curr_id
                           << " → 0x" << *maybe_stop;
                ctx.edges.insert(
                    edge_t{curr_id, *maybe_stop, edge_t::Type::FALLTHROUGH});
                ctx.reprove_subtree(*maybe_stop);
                continue;
            }
        }
        else
        {
            bb = explored_.at(curr_id);
            stats.bbs_cached++;
        }

        // ── Resolve targets ─────────────────────────────────────────────

        auto resolve_start = Clock::now();

        const synthetic_block_info_t *synthetic_info = nullptr;
        const lifted_bb_t *synthetic_predecessor_bb = nullptr;
        if (is_synthetic(curr_id))
        {
            auto synth_it = ctx.synthetic_blocks.find(curr_id);
            if (synth_it != ctx.synthetic_blocks.end())
            {
                synthetic_info = &synth_it->second;
                auto pred_it = explored_.find(synth_it->second.predecessor);
                if (pred_it != explored_.end())
                    synthetic_predecessor_bb = &pred_it->second;
            }
        }

        resolve_context_t rctx{
            .bb = bb,
            .entry_rva = entry_rva,
            .lift_ctx = ctx,
            .synthetic_info = synthetic_info,
            .synthetic_predecessor_bb = synthetic_predecessor_bb,
            .slice_module = {},
            .slice_cfg = nullptr,
            .concretized_slice = nullptr,
            .bin_ctx = *bin_ctx_};

        resolved_targets_result_t targets_result;
        if (auto hinted_targets = callbacks_->hint_resolve_targets(rctx))
        {
            targets_result = std::move(*hinted_targets);

            DLOG(INFO) << "lift: (fast-path) resolved " << targets_result.targets.size()
                       << " targets for 0x" << std::hex << curr_id;
        }
        else
        {
            auto clone = llvm::CloneModule(*bb_cache_module_);
            // Link helpers needed by the optimizer.
            if (auto err = helpers::link_deobfuscation_intrinsics(clone.get()))
                return std::move(err);
            if (auto err = helpers::link_ram_helpers(clone.get()))
                return std::move(err);
            if (auto err = helpers::link_state_utils(clone.get()))
                return std::move(err);
            if (auto err = helpers::link_lifting_helpers(clone.get()))
                return std::move(err);
            if (auto err = annotate_linked_state_helpers(*clone, *bin_ctx_, core_annotation_id_))
                return std::move(err);

            auto slice_cfg_or = build_backward_slice_cfg(
                clone.get(), bb.id,
                "__lifted_partial_cfg_" + llvm::utohexstr(bb.id), ctx);
            if (!slice_cfg_or)
                return slice_cfg_or.takeError();
            llvm::Function *slice_cfg = *slice_cfg_or;

            llvm::Function *concretized_slice = nullptr;
            if (slice_cfg)
            {
                auto concretized_or = concretize_cfg_base(
                    slice_cfg, 0, slice_cfg->getName().str() + "_rva_based");
                if (!concretized_or)
                    return concretized_or.takeError();
                concretized_slice = *concretized_or;
            }

            rctx.slice_module = std::move(clone);
            rctx.slice_cfg = slice_cfg;
            rctx.concretized_slice = concretized_slice;
            targets_result = callbacks_->resolve_targets(rctx);

            DLOG(INFO) << "lift: resolved " << targets_result.targets.size()
                       << " targets for 0x" << std::hex << curr_id;
        }

        stats.resolve_time_ms += elapsed_ms(resolve_start);

        // ── Handle resolved targets ─────────────────────────────────────

        for (const auto &target : targets_result.targets)
        {
            switch (target.type)
            {
            case resolved_target_t::Type::INTERNAL:
            {
                bb_id_t new_id = static_cast<bb_id_t>(target.dest);
                bool known = ctx.has_edge_between(curr_id, new_id);
                if (!known)
                {
                    auto edge_type = is_synthetic(curr_id)
                                         ? edge_t::Type::SYNTHETIC_RETURN
                                         : edge_t::Type::CONTROL_FLOW;
                    ctx.edges.insert(edge_t{curr_id, new_id, edge_type});
                }
                if (!explored_.count(new_id))
                    ctx.worklist.push_back(new_id);
                else if (!known)
                    ctx.reprove_subtree(new_id);
                break;
            }
            case resolved_target_t::Type::RECURSIVE:
            {
                if (ctx.recursive_synthetic_index.count(curr_id))
                    break; // already created
                bb_id_t disp_id = next_synthetic_id_++;
                ctx.synthetic_blocks[disp_id] = synthetic_block_info_t{
                    .type = synthetic_block_info_t::Type::RECURSIVE,
                    .dest_addr = ctx.entry_rva,
                    .annotation_id = ctx.entry_annotation_id,
                    .predecessor = curr_id};
                ctx.recursive_synthetic_index[curr_id] = disp_id;
                ctx.edges.insert(edge_t{curr_id, disp_id,
                                        edge_t::Type::SYNTHETIC_RECURSIVE_CALL});
                ctx.worklist.push_back(disp_id);
                break;
            }
            case resolved_target_t::Type::EXTERNAL:
            {
                if (!target.annotation_id)
                {
                    return llvm::make_error<llvm::StringError>(
                        "lift: resolved external target is missing an annotation",
                        llvm::inconvertibleErrorCode());
                }
                auto ext_key = std::make_pair(curr_id, target.dest);
                if (ctx.external_synthetic_index.count(ext_key))
                    break; // already created

                bb_id_t disp_id = next_synthetic_id_++;
                ctx.synthetic_blocks[disp_id] = synthetic_block_info_t{
                    .type = synthetic_block_info_t::Type::EXTERNAL,
                    .dest_addr = target.dest,
                    .annotation_id = *target.annotation_id,
                    .predecessor = curr_id};
                ctx.external_synthetic_index[ext_key] = disp_id;
                ctx.edges.insert(edge_t{curr_id, disp_id,
                                        edge_t::Type::SYNTHETIC_EXTERNAL});
                ctx.worklist.push_back(disp_id);
                break;
            }
            case resolved_target_t::Type::RETURN_TO_CALLER:
            {
                // Record this block as a ret-terminated caller-returning block.
                ctx.return_to_caller_blocks.insert(curr_id);
                break;
            }
            }
        }

        if (targets_result.indirect_annotation_id)
        {
            if (!ctx.indirect_synthetic_index.count(curr_id))
            {
                bb_id_t disp_id = next_synthetic_id_++;
                ctx.synthetic_blocks[disp_id] = synthetic_block_info_t{
                    .type = synthetic_block_info_t::Type::INDIRECT,
                    .dest_addr = std::nullopt,
                    .annotation_id = *targets_result.indirect_annotation_id,
                    .predecessor = curr_id};
                ctx.indirect_synthetic_index[curr_id] = disp_id;
                ctx.edges.insert(edge_t{curr_id, disp_id,
                                        edge_t::Type::SYNTHETIC_INDIRECT});
                ctx.worklist.push_back(disp_id);
            }
        }

    } // end main loop

    // ── Build final CFG ─────────────────────────────────────────────────

    auto stitch_start = Clock::now();

    auto final_module = llvm::CloneModule(*bb_cache_module_);
    if (auto err = helpers::link_state_utils(final_module.get()))
        return std::move(err);

    std::set<edge_t> reachable_edges;
    std::set<lifted_bb_t> reachable_blocks;
    auto final_func_or = build_forward_cfg(
        final_module.get(), entry_rva, "__lifted_rebuilt_cfg", ctx,
        config.instrument_bb_entry, &reachable_edges, &reachable_blocks);
    if (!final_func_or)
        return final_func_or.takeError();
    llvm::Function *final_func = *final_func_or;

    stats.stitch_time_ms = elapsed_ms(stitch_start);
    stats.bbs_total = reachable_blocks.size();
    stats.total_time_ms = elapsed_ms(total_start);

    auto concretize_entry_pc_result = concretize_entry_pc(final_func, 1, entry_rva);
    if (!concretize_entry_pc_result)
        return concretize_entry_pc_result.takeError();
    llvm::Function *public_func = concretize_entry_pc_result.get();
    if (auto err = annotate_lifted_function(*public_func, entry_annotation_id))
        return std::move(err);

    if (auto err = helpers::link_deobfuscation_intrinsics(final_module.get()))
        return std::move(err);
    if (auto err = helpers::link_ram_helpers(final_module.get()))
        return std::move(err);
    if (auto err = annotate_linked_state_helpers(*final_module, *bin_ctx_, entry_annotation_id))
        return std::move(err);

    callbacks_->on_function_built(public_func, ctx);

    return lift_result_t{
        .module = std::move(final_module),
        .lifted_function = public_func,
        .edges = std::move(reachable_edges),
        .basic_blocks = std::move(reachable_blocks),
        .synthetic_blocks = ctx.synthetic_blocks,
        .stats = stats};
}
} // namespace lifted::lifter
