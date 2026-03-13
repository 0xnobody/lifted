#include "test_framework.hpp"

#include "compat/lief_compat.hpp"

#include "abi/all_registers_cc.hpp"
#include "abi/systemv_x64.hpp"
#include "binary_context.hpp"
#include "lifter/lift_context.hpp"
#include "lifter/lifter_types.hpp"
#include "lifter/standard_lifter_callbacks.hpp"

#include <llvm/ADT/AddressRanges.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <fstream>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>

#ifndef EVAL_IOFILE_SO
#  error "EVAL_IOFILE_SO must be defined at compile time (path to libeval-iofile.so)"
#endif

namespace
{
using lifted::BinaryContext;
using lifted::INVALID_ANNOTATION_ID;
using lifted::annotation_id_t;
using lifted::fnc_annotation_t;
using lifted::lifter::StandardLifterCallbacks;
using lifted::lifter::lift_context_t;
using lifted::lifter::lifted_bb_t;
using lifted::lifter::resolve_context_t;
using lifted::lifter::resolved_target_t;
using lifted::lifter::standard_lifter_config_t;

struct ImportedFunctionInfo
{
    uint64_t    direct_addr = 0;
    uint64_t    slot_addr = 0;
    std::string raw_name;
    std::string base_name;
};

class ExposedCallbacks final : public StandardLifterCallbacks
{
  public:
    using StandardLifterCallbacks::StandardLifterCallbacks;
    using StandardLifterCallbacks::heuristically_extract_targets;
};

std::string error_to_string(llvm::Error err)
{
    if (!err)
        return {};
    return llvm::toString(std::move(err));
}

std::unique_ptr<LIEF::Binary> parse_binary(const char *path)
{
    return LIEF::Parser::parse(path);
}

std::filesystem::path write_temp_json(std::string_view stem,
                                      std::string_view json)
{
    auto path = std::filesystem::temp_directory_path() /
                ("lifted-annotations-" + std::string(stem) + ".json");
    std::ofstream out(path);
    out << json;
    out.close();
    return path;
}

annotation_id_t add_entry_annotation(BinaryContext &bin_ctx)
{
    auto ann = std::make_unique<fnc_annotation_t>();
    ann->name = "entry";
    ann->cc = &lifted::abi::SystemVx64CC::get();
    return bin_ctx.add_annotation(std::move(ann));
}

std::optional<ImportedFunctionInfo> find_printf_info(const LIEF::Binary &binary)
{
    ImportedFunctionInfo info;

    auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(&binary);
    if (!elf)
        return std::nullopt;

    for (const auto &reloc : elf->pltgot_relocations())
    {
        if (!reloc.has_symbol() || reloc.symbol() == nullptr)
            continue;
        if (reloc.symbol()->name().find("printf") == std::string::npos)
            continue;
        info.slot_addr = reloc.address();
        info.raw_name = reloc.symbol()->name();
        break;
    }

    if (info.raw_name.empty() || info.slot_addr == 0)
        return std::nullopt;

    auto at = info.raw_name.find('@');
    info.base_name = at == std::string::npos ? info.raw_name : info.raw_name.substr(0, at);

    auto direct_addr = binary.get_function_address(info.base_name);
    if (direct_addr)
        info.direct_addr = *direct_addr;
    return info;
}

std::optional<uint64_t> find_direct_addr_for_name(BinaryContext &bin_ctx,
                                                  const std::string &needle)
{
    auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(&bin_ctx.binary());
    if (!elf)
        return std::nullopt;

    for (const char *section_name : {".plt.sec", ".plt"})
    {
        auto *section = elf->get_section(section_name);
        if (!section)
            continue;

        uint64_t start = section->virtual_address();
        uint64_t end = start + section->size();
        for (uint64_t addr = start; addr < end; ++addr)
        {
            auto name = bin_ctx.symbol_name_at_rva(addr);
            if (name && name->find(needle) != std::string::npos)
                return addr;
        }
    }

    return std::nullopt;
}

llvm::Function *create_const_return_function(llvm::Module &module,
                                             llvm::StringRef name,
                                             uint64_t        value)
{
    auto &ctx = module.getContext();
    auto *fn = llvm::Function::Create(
        llvm::FunctionType::get(llvm::Type::getInt64Ty(ctx), false),
        llvm::GlobalValue::ExternalLinkage,
        name,
        module);
    auto *bb = llvm::BasicBlock::Create(ctx, "entry", fn);
    llvm::IRBuilder<> b(bb);
    b.CreateRet(b.getInt64(value));
    return fn;
}

llvm::Function *create_indirect_return_function(llvm::Module &module,
                                                llvm::StringRef name,
                                                uint64_t        slot_addr)
{
    auto &ctx = module.getContext();
    auto *ram_ty = llvm::ArrayType::get(llvm::Type::getInt8Ty(ctx), slot_addr + 8);
    auto *ram = new llvm::GlobalVariable(module,
                                         ram_ty,
                                         false,
                                         llvm::GlobalValue::ExternalLinkage,
                                         llvm::Constant::getNullValue(ram_ty),
                                         "RAM");

    auto *fn = llvm::Function::Create(
        llvm::FunctionType::get(llvm::Type::getInt64Ty(ctx), false),
        llvm::GlobalValue::ExternalLinkage,
        name,
        module);
    auto *bb = llvm::BasicBlock::Create(ctx, "entry", fn);
    llvm::IRBuilder<> b(bb);
    auto *gep = b.CreateGEP(ram_ty, ram, {b.getInt64(0), b.getInt64(slot_addr)}, "got_slot");
    auto *load = b.CreateLoad(llvm::Type::getInt64Ty(ctx), gep, "loaded_target");
    b.CreateRet(load);
    return fn;
}

resolve_context_t make_resolve_context(const lifted_bb_t &bb,
                                       uint64_t           entry_rva,
                                       lift_context_t    &lift_ctx,
                                       BinaryContext     &bin_ctx)
{
    return resolve_context_t{
        bb,
        entry_rva,
        lift_ctx,
        std::unique_ptr<llvm::Module>{},
        nullptr,
        nullptr,
        bin_ctx,
    };
}

resolved_target_t only_target(const lifted::lifter::resolved_targets_result_t &result)
{
    CHECK_EQ(result.targets.size(), static_cast<size_t>(1));
    if (result.targets.empty())
        return resolved_target_t{.type = resolved_target_t::Type::INTERNAL, .dest = 0, .annotation_id = std::nullopt};
    return result.targets.front();
}

} // namespace

TEST(binary_context_json_import_indexes_and_ccs)
{
    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    BinaryContext bin_ctx(std::move(binary));
    auto json_path = write_temp_json(
        "success",
        R"json([
  {
    "name": "printf@GLIBC_2.2.5",
    "rva": "0x10e0",
    "dispatcher_rva": "0x401234",
    "cc": "systemv_x64",
    "reads_global_memory": true,
    "ptr_params": {
      "0": {"read": true, "written": false, "captured": false, "fixed_size": 16}
    },
    "ret_ptr": {"is_fresh_alloc": true},
    "ret_size_bytes": 8
  },
  {
    "name": "observer",
    "cc": "all_regs"
  }
])json");

    auto err = bin_ctx.import_annotations_from_json(json_path);
    CHECK(!err);
    if (err)
        return;

    auto printf_id = bin_ctx.get_by_name("printf@GLIBC_2.2.5");
    CHECK_NE(printf_id, INVALID_ANNOTATION_ID);
    CHECK_EQ(printf_id, bin_ctx.get_by_name("printf"));
    CHECK_EQ(printf_id, bin_ctx.get_ext_call(0x10e0));
    CHECK_EQ(printf_id, bin_ctx.get_indr_call(0x401234));

    auto *printf_ann = bin_ctx.get_by_id(printf_id);
    CHECK(printf_ann != nullptr);
    if (printf_ann)
    {
        CHECK(printf_ann->cc == &lifted::abi::SystemVx64CC::get());
        CHECK(printf_ann->reads_global_memory);
        CHECK(printf_ann->ptr_params.count(0) == 1);
        CHECK(printf_ann->ret_ptr.has_value());
        CHECK_EQ(printf_ann->ret_size_bytes, static_cast<uint8_t>(8));
    }

    auto observer_id = bin_ctx.get_by_name("observer");
    CHECK_NE(observer_id, INVALID_ANNOTATION_ID);
    auto *observer_ann = bin_ctx.get_by_id(observer_id);
    CHECK(observer_ann != nullptr);
    if (observer_ann)
        CHECK(observer_ann->cc == &lifted::abi::AllRegistersCC::get());

    std::filesystem::remove(json_path);
}

TEST(binary_context_json_import_rejects_conflicts_and_unknown_cc)
{
    auto expect_import_error = [](std::string_view stem,
                                  std::string_view json,
                                  std::string_view needle)
    {
        auto binary = parse_binary(EVAL_IOFILE_SO);
        CHECK(binary != nullptr);
        if (!binary)
            return;

        BinaryContext bin_ctx(std::move(binary));
        auto json_path = write_temp_json(stem, json);
        auto err = bin_ctx.import_annotations_from_json(json_path);
        CHECK(static_cast<bool>(err));
        std::string message = error_to_string(std::move(err));
        CHECK(message.find(needle) != std::string::npos);
        CHECK_EQ(bin_ctx.get_by_name("printf"), INVALID_ANNOTATION_ID);
        std::filesystem::remove(json_path);
    };

    expect_import_error(
        "dup-name",
        R"json([
  {"name": "printf", "cc": "systemv_x64"},
  {"name": "printf", "cc": "systemv_x64"}
])json",
        "duplicate imported annotation name/alias");

    expect_import_error(
        "alias-collision",
        R"json([
  {"name": "printf@GLIBC_2.2.5", "cc": "systemv_x64"},
  {"name": "printf", "cc": "systemv_x64"}
])json",
        "duplicate imported annotation name/alias");

    expect_import_error(
        "dup-rva",
        R"json([
  {"name": "first", "rva": "0x10", "cc": "systemv_x64"},
  {"name": "second", "rva": 16, "cc": "systemv_x64"}
])json",
        "duplicate imported annotation rva");

    expect_import_error(
        "dup-dispatcher",
        R"json([
  {"name": "first", "dispatcher_rva": "0x40", "cc": "systemv_x64"},
  {"name": "second", "dispatcher_rva": 64, "cc": "systemv_x64"}
])json",
        "duplicate imported annotation dispatcher_rva");

    expect_import_error(
        "bad-cc",
        R"json([
  {"name": "printf", "cc": "bogus"}
])json",
        "unknown calling convention");
}

TEST(binary_context_import_slot_lookup_and_version_alias)
{
    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    auto info = find_printf_info(*binary);
    CHECK(info.has_value());
    if (!info)
        return;

    BinaryContext bin_ctx(std::move(binary));
    CHECK_EQ(bin_ctx.import_name_for_slot(info->slot_addr).value_or(""), info->raw_name);
    auto direct_addr = find_direct_addr_for_name(bin_ctx, info->base_name);
    CHECK(direct_addr.has_value());

    auto json_path = write_temp_json(
        "version-alias",
        R"json([
  {"name": "printf", "cc": "systemv_x64"}
])json");
    auto err = bin_ctx.import_annotations_from_json(json_path);
    CHECK(!err);
    if (err)
        return;

    auto unversioned_id = bin_ctx.get_by_name(info->base_name);
    CHECK_NE(unversioned_id, INVALID_ANNOTATION_ID);
    CHECK_EQ(unversioned_id, bin_ctx.get_by_name(info->raw_name));

    std::filesystem::remove(json_path);
}

TEST(callbacks_direct_external_use_imported_name_and_fallback_name)
{
    auto import_json = R"json([
  {"name": "printf", "cc": "systemv_x64"}
])json";

    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;
    auto info = find_printf_info(*binary);
    CHECK(info.has_value());
    if (!info)
        return;

    BinaryContext imported_ctx(std::move(binary));
    auto imported_direct_addr = find_direct_addr_for_name(imported_ctx, info->base_name);
    CHECK(imported_direct_addr.has_value());
    if (!imported_direct_addr)
        return;

    auto json_path = write_temp_json("direct-name", import_json);
    auto import_err = imported_ctx.import_annotations_from_json(json_path);
    CHECK(!import_err);
    if (import_err)
        return;

    annotation_id_t entry_id = add_entry_annotation(imported_ctx);
    lift_context_t lift_ctx{};
    lift_ctx.entry_annotation_id = entry_id;

    standard_lifter_config_t config{};
    config.ext_func_rva_ranges.insert(llvm::AddressRange{*imported_direct_addr, *imported_direct_addr + 1});
    ExposedCallbacks callbacks(config);

    llvm::LLVMContext llvm_ctx;
    auto module = std::make_unique<llvm::Module>("direct-name", llvm_ctx);
    llvm::Function *fn = create_const_return_function(*module, "direct_call", *imported_direct_addr);
    lifted_bb_t bb{
        .type = lifted_bb_t::Type::REAL,
        .id = 0x5000,
        .func_name = "bb_direct",
        .rva_range = std::nullopt,
        .terminating_category = remill::Instruction::kCategoryDirectFunctionCall,
        .was_truncated_by_stop = false,
    };
    auto ctx = make_resolve_context(bb, /*entry_rva=*/0x1234, lift_ctx, imported_ctx);
    auto result = callbacks.heuristically_extract_targets(*fn, ctx);
    CHECK(static_cast<bool>(result));
    auto target = only_target(result);
    CHECK_EQ(target.type, resolved_target_t::Type::EXTERNAL);
    CHECK(target.annotation_id.has_value());
    if (target.annotation_id)
        CHECK_EQ(*target.annotation_id, imported_ctx.get_by_name("printf"));

    std::filesystem::remove(json_path);

    auto fallback_binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(fallback_binary != nullptr);
    if (!fallback_binary)
        return;
    BinaryContext fallback_ctx(std::move(fallback_binary));
    auto fallback_direct_addr = find_direct_addr_for_name(fallback_ctx, info->base_name);
    CHECK(fallback_direct_addr.has_value());
    if (!fallback_direct_addr)
        return;

    annotation_id_t fallback_entry_id = add_entry_annotation(fallback_ctx);
    lift_context_t fallback_lift_ctx{};
    fallback_lift_ctx.entry_annotation_id = fallback_entry_id;
    llvm::LLVMContext fallback_llvm_ctx;
    auto fallback_module = std::make_unique<llvm::Module>("direct-fallback", fallback_llvm_ctx);
    llvm::Function *fallback_fn = create_const_return_function(*fallback_module, "direct_fallback", *fallback_direct_addr);
    auto fallback_ctx_obj = make_resolve_context(bb, /*entry_rva=*/0x1234, fallback_lift_ctx, fallback_ctx);
    auto fallback_result = callbacks.heuristically_extract_targets(*fallback_fn, fallback_ctx_obj);
    CHECK(static_cast<bool>(fallback_result));
    auto fallback_target = only_target(fallback_result);
    CHECK(fallback_target.annotation_id.has_value());
    if (!fallback_target.annotation_id)
        return;

    auto inferred_name = fallback_ctx.symbol_name_at_rva(*fallback_direct_addr);
    CHECK(inferred_name.has_value());
    auto *fallback_ann = fallback_ctx.get_by_id(*fallback_target.annotation_id);
    CHECK(fallback_ann != nullptr);
    if (fallback_ann && inferred_name)
        CHECK_EQ(fallback_ann->name, *inferred_name);
}

TEST(callbacks_indirect_import_name_dispatcher_override_and_fallback_name)
{
    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;
    auto info = find_printf_info(*binary);
    CHECK(info.has_value());
    if (!info)
        return;

    standard_lifter_config_t config{};
    config.got_table_rva_ranges.insert(llvm::AddressRange{info->slot_addr, info->slot_addr + 1});
    ExposedCallbacks callbacks(config);

    llvm::LLVMContext llvm_ctx;
    auto module = std::make_unique<llvm::Module>("indirect-imported", llvm_ctx);
    llvm::Function *fn = create_indirect_return_function(*module, "indirect_imported", info->slot_addr);
    lifted_bb_t bb{
        .type = lifted_bb_t::Type::REAL,
        .id = 0x9000,
        .func_name = "bb_indirect",
        .rva_range = std::nullopt,
        .terminating_category = remill::Instruction::kCategoryIndirectFunctionCall,
        .was_truncated_by_stop = false,
    };

    auto imported_binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(imported_binary != nullptr);
    if (!imported_binary)
        return;
    BinaryContext imported_ctx(std::move(imported_binary));
    auto json_path = write_temp_json(
        "indirect-name",
        R"json([
  {"name": "printf", "cc": "systemv_x64"}
])json");
    auto import_err = imported_ctx.import_annotations_from_json(json_path);
    CHECK(!import_err);
    if (import_err)
        return;
    lift_context_t imported_lift_ctx{};
    imported_lift_ctx.entry_annotation_id = add_entry_annotation(imported_ctx);
    auto imported_resolve_ctx = make_resolve_context(bb, /*entry_rva=*/0x1234, imported_lift_ctx, imported_ctx);
    auto imported_result = callbacks.heuristically_extract_targets(*fn, imported_resolve_ctx);
    CHECK(imported_result.indirect_annotation_id.has_value());
    if (imported_result.indirect_annotation_id)
        CHECK_EQ(*imported_result.indirect_annotation_id, imported_ctx.get_by_name("printf"));
    std::filesystem::remove(json_path);

    auto override_binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(override_binary != nullptr);
    if (!override_binary)
        return;
    BinaryContext override_ctx(std::move(override_binary));
    auto override_json_path = write_temp_json(
        "indirect-override",
        R"json([
  {"name": "printf", "cc": "systemv_x64"},
  {"name": "manual_dispatch", "dispatcher_rva": "0x9000", "cc": "all_regs"}
])json");
    auto override_err = override_ctx.import_annotations_from_json(override_json_path);
    CHECK(!override_err);
    if (override_err)
        return;
    lift_context_t override_lift_ctx{};
    override_lift_ctx.entry_annotation_id = add_entry_annotation(override_ctx);
    auto override_resolve_ctx = make_resolve_context(bb, /*entry_rva=*/0x1234, override_lift_ctx, override_ctx);
    auto override_result = callbacks.heuristically_extract_targets(*fn, override_resolve_ctx);
    CHECK(override_result.indirect_annotation_id.has_value());
    if (override_result.indirect_annotation_id)
        CHECK_EQ(*override_result.indirect_annotation_id, override_ctx.get_by_name("manual_dispatch"));
    std::filesystem::remove(override_json_path);

    auto fallback_binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(fallback_binary != nullptr);
    if (!fallback_binary)
        return;
    BinaryContext fallback_ctx(std::move(fallback_binary));
    lift_context_t fallback_lift_ctx{};
    fallback_lift_ctx.entry_annotation_id = add_entry_annotation(fallback_ctx);
    auto fallback_resolve_ctx = make_resolve_context(bb, /*entry_rva=*/0x1234, fallback_lift_ctx, fallback_ctx);
    auto fallback_result = callbacks.heuristically_extract_targets(*fn, fallback_resolve_ctx);
    CHECK(fallback_result.indirect_annotation_id.has_value());
    if (!fallback_result.indirect_annotation_id)
        return;

    auto inferred_name = fallback_ctx.import_name_for_slot(info->slot_addr);
    CHECK(inferred_name.has_value());
    auto *fallback_ann = fallback_ctx.get_by_id(*fallback_result.indirect_annotation_id);
    CHECK(fallback_ann != nullptr);
    if (fallback_ann && inferred_name)
        CHECK_EQ(fallback_ann->name, *inferred_name);
}
