#include "test_framework.hpp"

#include "compat/lief_compat.hpp"

#include "abi/systemv_x64.hpp"
#include "binary_context.hpp"
#include "lifter/lifter.hpp"
#include "lifter/standard_lifter_callbacks.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Error.h>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#ifndef EVAL_EXT_CALL_SO
#  error "EVAL_EXT_CALL_SO must be defined at compile time (path to libeval-ext-call.so)"
#endif

namespace
{
std::optional<uint64_t> find_export_va(LIEF::Binary &binary,
                                       const std::string &sym_name)
{
    auto r = binary.get_function_address(sym_name);
    if (!r)
        return std::nullopt;
    return *r;
}

template <typename T>
T unwrapExpected(llvm::Expected<T> value)
{
    CHECK(static_cast<bool>(value));
    if (!value)
    {
        llvm::consumeError(value.takeError());
        return T{};
    }
    return *value;
}

const lifted::lifter::lifted_bb_t *find_basic_block(const lifted::lifter::lift_result_t &result,
                                                    lifted::lifter::bb_id_t id)
{
    for (const auto &block : result.basic_blocks)
        if (block.id == id)
            return &block;
    return nullptr;
}
std::optional<unsigned> state_gpr_slot_for_reg(lifted::abi::ABIRegister reg)
{
    switch (reg)
    {
    case lifted::abi::ABIRegister::RBX:
        return 3;
    case lifted::abi::ABIRegister::RBP:
        return 15;
    case lifted::abi::ABIRegister::R12:
        return 25;
    case lifted::abi::ABIRegister::R13:
        return 27;
    case lifted::abi::ABIRegister::R14:
        return 29;
    case lifted::abi::ABIRegister::R15:
        return 31;
    default:
        return std::nullopt;
    }
}

std::optional<unsigned> state_gpr_slot_from_pointer(const llvm::Value *pointer)
{
    auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(pointer);
    if (!gep)
        return std::nullopt;

    auto *last_index = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(gep->getNumOperands() - 1));
    if (!last_index)
        return std::nullopt;

    return static_cast<unsigned>(last_index->getZExtValue());
}
} // namespace

TEST(opaque_call_stub_preserves_systemv_nonvolatile_registers)
{
    const std::filesystem::path so_path = EVAL_EXT_CALL_SO;

    auto binary = LIEF::Parser::parse(so_path);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    auto entry_va = find_export_va(*binary, "test");
    CHECK(entry_va.has_value());
    if (!entry_va)
        return;

    llvm::LLVMContext ctx;
    auto arch = remill::Arch::Get(
        ctx, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
    CHECK(arch != nullptr);
    if (!arch)
        return;

    lifted::BinaryContext bin_ctx(std::move(binary));
    auto entry_annotation = std::make_unique<lifted::fnc_annotation_t>();
    entry_annotation->cc = &lifted::abi::SystemVx64CC::get();
    auto entry_annotation_id = bin_ctx.add_annotation(std::move(entry_annotation));

    lifted::lifter::standard_lifter_config_t cb_config{};
    lifted::lifter::StandardLifterCallbacks callbacks(std::move(cb_config));

    auto lifter_or = lifted::lifter::Lifter::create(arch.get(), bin_ctx, &callbacks);
    CHECK(static_cast<bool>(lifter_or));
    if (!lifter_or)
    {
        llvm::consumeError(lifter_or.takeError());
        return;
    }

    auto result_or = lifter_or->lift(*entry_va, entry_annotation_id);
    CHECK(static_cast<bool>(result_or));
    if (!result_or)
    {
        llvm::consumeError(result_or.takeError());
        return;
    }

    auto result = std::move(*result_or);
    CHECK(result.module != nullptr);
    if (!result.module)
        return;

    const llvm::Module &stub_module = lifter_or->bb_cache();
    const lifted::lifter::synthetic_block_info_t *external_info = nullptr;
    const lifted::lifter::lifted_bb_t *external_block = nullptr;
    for (const auto &[id, info] : result.synthetic_blocks)
    {
        if (info.type != lifted::lifter::synthetic_block_info_t::Type::EXTERNAL)
            continue;
        CHECK(external_info == nullptr);
        if (!external_info)
        {
            external_info = &info;
            external_block = find_basic_block(result, id);
        }
    }
    CHECK(external_info != nullptr);
    CHECK(external_block != nullptr);
    if (!external_info || !external_block)
        return;

    auto *wrapper = stub_module.getFunction(external_block->func_name);
    CHECK(wrapper != nullptr);
    const auto *annotation = bin_ctx.get_by_id(external_info->annotation_id);
    CHECK(annotation != nullptr);
    if (!wrapper || !annotation || annotation->name.empty())
        return;

    auto *opaque_target = stub_module.getFunction("__lifted_ext_call_" + annotation->name);
    CHECK(opaque_target != nullptr);
    if (!opaque_target)
        return;
    const llvm::Instruction *opaque_call_inst = nullptr;
    for (const auto &bb : *wrapper)
    {
        for (const auto &inst : bb)
        {
            auto *call = llvm::dyn_cast<llvm::CallBase>(&inst);
            if (!call || call->getCalledFunction() != opaque_target)
                continue;
            CHECK(opaque_call_inst == nullptr);
            if (!opaque_call_inst)
                opaque_call_inst = &inst;
        }
    }
    CHECK(opaque_call_inst != nullptr);
    if (!opaque_call_inst)
        return;

    // The stub is always-inline, so the non-volatile save/restore sequence is
    // observable in the synthetic external wrapper cached by the lifter.
    const auto &cc = lifted::abi::SystemVx64CC::get();
    for (auto reg : cc.getNonVolatileRegisters())
    {
        auto slot = state_gpr_slot_for_reg(reg);
        CHECK(slot.has_value());
        if (!slot)
            return;

        bool extracted_before_opaque_call = false;
        bool stored_after_opaque_call = false;
        bool past_opaque_call = false;
        for (const auto &bb : *wrapper)
        {
            for (const auto &inst : bb)
            {
                if (&inst == opaque_call_inst)
                {
                    past_opaque_call = true;
                    continue;
                }

                if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&inst))
                {
                    if (!past_opaque_call && state_gpr_slot_from_pointer(load->getPointerOperand()) == slot)
                        extracted_before_opaque_call = true;
                }
                if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst))
                {
                    if (past_opaque_call && state_gpr_slot_from_pointer(store->getPointerOperand()) == slot)
                        stored_after_opaque_call = true;
                }
            }
        }

        CHECK(extracted_before_opaque_call);
        CHECK(stored_after_opaque_call);
    }
}
