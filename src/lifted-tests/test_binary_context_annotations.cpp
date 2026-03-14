#include "test_framework.hpp"

#include "compat/lief_compat.hpp"

#include "abi/all_registers_cc.hpp"
#include "abi/systemv_x64.hpp"
#include "binary_context.hpp"
#include "lifter/lift_context.hpp"
#include "lifter/lifter.hpp"
#include "lifter/lifter_types.hpp"
#include "lifter/standard_lifter_callbacks.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
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
#include <string_view>
#include <utility>
#include <vector>

#ifndef EVAL_IOFILE_SO
#  error "EVAL_IOFILE_SO must be defined at compile time (path to libeval-iofile.so)"
#endif

namespace
{
using lifted::BinaryContext;
using lifted::INVALID_ANNOTATION_ID;
using lifted::annotation_id_t;
using lifted::fnc_annotation_t;
using lifted::lifter::Lifter;
using lifted::lifter::StandardLifterCallbacks;
using lifted::lifter::edge_t;
using lifted::lifter::lift_context_t;
using lifted::lifter::lift_result_t;
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

llvm::Error import_json(BinaryContext   &bin_ctx,
                        std::string_view stem,
                        std::string_view json)
{
    auto json_path = write_temp_json(stem, json);
    auto err = bin_ctx.import_annotations_from_json(json_path);
    std::filesystem::remove(json_path);
    return err;
}

std::string hex_string(uint64_t value)
{
    return "0x" + llvm::utohexstr(value);
}

std::string quoted_hex_string(uint64_t value)
{
    return "\"" + hex_string(value) + "\"";
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

std::optional<uint64_t> find_export_va(LIEF::Binary &binary,
                                       const std::string &sym_name)
{
    auto r = binary.get_function_address(sym_name);
    if (!r)
        return std::nullopt;
    return *r;
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

std::vector<uint64_t> collect_external_call_site_rvas(const lift_result_t &result)
{
    std::vector<uint64_t> sites;
    for (const auto &edge : result.edges)
    {
        if (edge.type != edge_t::Type::SYNTHETIC_EXTERNAL)
            continue;
        bool seen = false;
        for (uint64_t existing : sites)
        {
            if (existing == edge.source)
            {
                seen = true;
                break;
            }
        }
        if (!seen)
            sites.push_back(edge.source);
    }
    return sites;
}

std::shared_ptr<const remill::Arch> make_x86_64_linux_arch(llvm::LLVMContext &ctx)
{
    return remill::Arch::Get(ctx, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
}

} // namespace

TEST(binary_context_imports_canonical_annotations_and_bindings)
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
    auto direct_addr = find_direct_addr_for_name(bin_ctx, info->base_name);
    CHECK(direct_addr.has_value());
    if (!direct_addr)
        return;

    auto standard_err = import_json(
        bin_ctx,
        "layered-standard",
        R"json({
  "annotations": [
    {
      "name": "printf@GLIBC_2.2.5",
      "cc": "systemv_x64",
      "is_variadic": true,
      "arg_count": 6,
      "reads_global_memory": true,
      "ptr_params": {
        "0": {"read": true, "written": false, "captured": false, "fixed_size": 16}
      },
      "ret_ptr": {"is_fresh_alloc": true},
      "ret_size_bytes": 8
    },
    {
      "name": "puts",
      "cc": "systemv_x64",
      "arg_count": 1
    }
  ]
})json");
    CHECK(!standard_err);
    if (standard_err)
        return;

    std::string binding_json =
        std::string(R"json({
  "bindings": [
    {"annotation": "printf", "rva": )json") + quoted_hex_string(*direct_addr) +
        std::string(R"json(},
    {"annotation": "puts", "site_rva": "0x401234"}
  ]
})json");

    auto binding_err = import_json(bin_ctx, "layered-bindings", binding_json);
    CHECK(!binding_err);
    if (binding_err)
        return;

    auto printf_id = bin_ctx.get_by_name("printf");
    auto puts_id = bin_ctx.get_by_name("puts");
    CHECK_NE(printf_id, INVALID_ANNOTATION_ID);
    CHECK_NE(puts_id, INVALID_ANNOTATION_ID);
    CHECK_EQ(printf_id, bin_ctx.get_by_name("printf@GLIBC_2.2.5"));
    CHECK_EQ(printf_id, bin_ctx.get_ext_call(*direct_addr));
    CHECK_EQ(puts_id, bin_ctx.get_site_call(0x401234));

    auto *printf_ann = bin_ctx.get_by_id(printf_id);
    auto *puts_ann = bin_ctx.get_by_id(puts_id);
    CHECK(printf_ann != nullptr);
    CHECK(puts_ann != nullptr);
    if (printf_ann)
    {
        CHECK(printf_ann->cc == &lifted::abi::SystemVx64CC::get());
        CHECK(printf_ann->reads_global_memory);
        CHECK(printf_ann->is_variadic);
        CHECK(printf_ann->arg_count.has_value());
        if (printf_ann->arg_count)
            CHECK_EQ(*printf_ann->arg_count, static_cast<uint8_t>(6));
        CHECK(printf_ann->ptr_params.count(0) == 1);
        CHECK(printf_ann->ret_ptr.has_value());
        CHECK_EQ(printf_ann->ret_size_bytes, static_cast<uint8_t>(8));
    }
    if (puts_ann)
    {
        CHECK(puts_ann->cc == &lifted::abi::SystemVx64CC::get());
        CHECK(!puts_ann->is_variadic);
        CHECK(puts_ann->arg_count.has_value());
        if (puts_ann->arg_count)
            CHECK_EQ(*puts_ann->arg_count, static_cast<uint8_t>(1));
    }
}

TEST(binary_context_binding_override_materializes_internal_derived_annotation)
{
    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    BinaryContext bin_ctx(std::move(binary));
    auto standard_err = import_json(
        bin_ctx,
        "derived-standard",
        R"json({
  "annotations": [
    {
      "name": "printf",
      "cc": "systemv_x64",
      "reads_global_memory": true,
      "writes_global_memory": false,
      "is_variadic": true,
      "arg_count": 6
    }
  ]
})json");
    CHECK(!standard_err);
    if (standard_err)
        return;

    auto binding_err = import_json(
        bin_ctx,
        "derived-binding",
        R"json({
  "bindings": [
    {
      "annotation": "printf",
      "site_rva": "0x401000",
      "override": {
        "arg_count": 2,
        "volatile_call": false
      }
    }
  ]
})json");
    CHECK(!binding_err);
    if (binding_err)
        return;

    auto base_id = bin_ctx.get_by_name("printf");
    auto site_id = bin_ctx.get_site_call(0x401000);
    CHECK_NE(base_id, INVALID_ANNOTATION_ID);
    CHECK_NE(site_id, INVALID_ANNOTATION_ID);
    CHECK_NE(site_id, base_id);

    auto *base_ann = bin_ctx.get_by_id(base_id);
    auto *site_ann = bin_ctx.get_by_id(site_id);
    CHECK(base_ann != nullptr);
    CHECK(site_ann != nullptr);
    if (!base_ann || !site_ann)
        return;

    std::string expected_derived_name = "printf_" + llvm::utohexstr(static_cast<uint64_t>(0x401000));
    CHECK_EQ(base_ann->name, std::string("printf"));
    CHECK_EQ(site_ann->name, expected_derived_name);
    CHECK_EQ(bin_ctx.get_by_name(expected_derived_name), INVALID_ANNOTATION_ID);
    CHECK(site_ann->cc == base_ann->cc);
    CHECK(site_ann->reads_global_memory == base_ann->reads_global_memory);
    CHECK(site_ann->writes_global_memory == base_ann->writes_global_memory);
    CHECK(site_ann->is_variadic == base_ann->is_variadic);
    CHECK(site_ann->volatile_call == false);
    CHECK(base_ann->volatile_call == true);
    CHECK(base_ann->arg_count.has_value());
    CHECK(site_ann->arg_count.has_value());
    if (base_ann->arg_count && site_ann->arg_count)
    {
        CHECK_EQ(*base_ann->arg_count, static_cast<uint8_t>(6));
        CHECK_EQ(*site_ann->arg_count, static_cast<uint8_t>(2));
    }
}

TEST(binary_context_json_import_rejects_conflicts_and_unknown_fields)
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
        auto err = import_json(bin_ctx, stem, json);
        CHECK(static_cast<bool>(err));
        std::string message = error_to_string(std::move(err));
        CHECK(message.find(needle) != std::string::npos);
        CHECK_EQ(bin_ctx.get_by_name("printf"), INVALID_ANNOTATION_ID);
    };

    expect_import_error(
        "dup-name",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64"},
    {"name": "printf", "cc": "systemv_x64"}
  ]
})json",
        "duplicate imported annotation name/alias");

    expect_import_error(
        "alias-collision",
        R"json({
  "annotations": [
    {"name": "printf@GLIBC_2.2.5", "cc": "systemv_x64"},
    {"name": "printf", "cc": "systemv_x64"}
  ]
})json",
        "duplicate imported annotation name/alias");

    expect_import_error(
        "dup-rva",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64"},
    {"name": "puts", "cc": "systemv_x64"}
  ],
  "bindings": [
    {"annotation": "printf", "rva": "0x10"},
    {"annotation": "puts", "rva": 16}
  ]
})json",
        "duplicate imported annotation rva");

    expect_import_error(
        "dup-site",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64"},
    {"name": "puts", "cc": "systemv_x64"}
  ],
  "bindings": [
    {"annotation": "printf", "site_rva": "0x40"},
    {"annotation": "puts", "site_rva": 64}
  ]
})json",
        "duplicate imported annotation site_rva");

    expect_import_error(
        "unknown-binding-target",
        R"json({
  "bindings": [
    {"annotation": "printf", "site_rva": "0x40"}
  ]
})json",
        "binding references unknown annotation");

    expect_import_error(
        "override-unknown-key",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64"}
  ],
  "bindings": [
    {
      "annotation": "printf",
      "site_rva": "0x40",
      "override": {"annotation": "printf"}
    }
  ]
})json",
        "unknown key 'annotation'");

    expect_import_error(
        "bad-cc",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "bogus"}
  ]
})json",
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

    auto err = import_json(
        bin_ctx,
        "version-alias",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64"}
  ]
})json");
    CHECK(!err);
    if (err)
        return;

    auto unversioned_id = bin_ctx.get_by_name(info->base_name);
    CHECK_NE(unversioned_id, INVALID_ANNOTATION_ID);
    CHECK_EQ(unversioned_id, bin_ctx.get_by_name(info->raw_name));
}

TEST(callbacks_direct_external_site_binding_beats_callee_binding)
{
    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;

    auto info = find_printf_info(*binary);
    CHECK(info.has_value());
    if (!info)
        return;

    BinaryContext imported_ctx(std::move(binary));
    auto direct_addr = find_direct_addr_for_name(imported_ctx, info->base_name);
    CHECK(direct_addr.has_value());
    if (!direct_addr)
        return;

    auto standard_err = import_json(
        imported_ctx,
        "direct-standard",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64", "is_variadic": true, "arg_count": 6}
  ]
})json");
    CHECK(!standard_err);
    if (standard_err)
        return;

    std::string binding_json =
        std::string(R"json({
  "bindings": [
    {"annotation": "printf", "rva": )json") + quoted_hex_string(*direct_addr) +
        std::string(R"json(},
    {"annotation": "printf", "site_rva": "0x5000", "override": {"arg_count": 2}}
  ]
})json");
    auto binding_err = import_json(imported_ctx, "direct-bindings", binding_json);
    CHECK(!binding_err);
    if (binding_err)
        return;

    auto callee_id = imported_ctx.get_ext_call(*direct_addr);
    auto site_id = imported_ctx.get_site_call(0x5000);
    CHECK_NE(callee_id, INVALID_ANNOTATION_ID);
    CHECK_NE(site_id, INVALID_ANNOTATION_ID);
    CHECK_NE(site_id, callee_id);

    annotation_id_t entry_id = add_entry_annotation(imported_ctx);
    lift_context_t lift_ctx{};
    lift_ctx.entry_annotation_id = entry_id;

    standard_lifter_config_t config{};
    config.ext_func_rva_ranges.insert(llvm::AddressRange{*direct_addr, *direct_addr + 1});
    ExposedCallbacks callbacks(config);

    llvm::LLVMContext llvm_ctx;
    auto module = std::make_unique<llvm::Module>("direct-site-override", llvm_ctx);
    llvm::Function *fn = create_const_return_function(*module, "direct_call", *direct_addr);
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
        CHECK_EQ(*target.annotation_id, site_id);

    auto *site_ann = imported_ctx.get_by_id(site_id);
    CHECK(site_ann != nullptr);
    if (site_ann)
    {
        CHECK(site_ann->arg_count.has_value());
        if (site_ann->arg_count)
            CHECK_EQ(*site_ann->arg_count, static_cast<uint8_t>(2));
    }

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

TEST(callbacks_indirect_import_name_and_site_binding_precedence)
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
    auto standard_err = import_json(
        imported_ctx,
        "indirect-standard",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64", "is_variadic": true, "arg_count": 6}
  ]
})json");
    CHECK(!standard_err);
    if (standard_err)
        return;

    lift_context_t imported_lift_ctx{};
    imported_lift_ctx.entry_annotation_id = add_entry_annotation(imported_ctx);
    auto imported_resolve_ctx = make_resolve_context(bb, /*entry_rva=*/0x1234, imported_lift_ctx, imported_ctx);
    auto imported_result = callbacks.heuristically_extract_targets(*fn, imported_resolve_ctx);
    CHECK(imported_result.indirect_annotation_id.has_value());
    if (imported_result.indirect_annotation_id)
        CHECK_EQ(*imported_result.indirect_annotation_id, imported_ctx.get_by_name("printf"));

    auto override_binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(override_binary != nullptr);
    if (!override_binary)
        return;

    BinaryContext override_ctx(std::move(override_binary));
    auto override_standard_err = import_json(
        override_ctx,
        "indirect-override-standard",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64", "is_variadic": true, "arg_count": 6}
  ]
})json");
    CHECK(!override_standard_err);
    if (override_standard_err)
        return;

    auto override_binding_err = import_json(
        override_ctx,
        "indirect-override-binding",
        R"json({
  "bindings": [
    {"annotation": "printf", "site_rva": "0x9000", "override": {"arg_count": 4}}
  ]
})json");
    CHECK(!override_binding_err);
    if (override_binding_err)
        return;

    auto site_id = override_ctx.get_site_call(0x9000);
    auto base_id = override_ctx.get_by_name("printf");
    CHECK_NE(site_id, INVALID_ANNOTATION_ID);
    CHECK_NE(site_id, base_id);

    lift_context_t override_lift_ctx{};
    override_lift_ctx.entry_annotation_id = add_entry_annotation(override_ctx);
    auto override_resolve_ctx = make_resolve_context(bb, /*entry_rva=*/0x1234, override_lift_ctx, override_ctx);
    auto override_result = callbacks.heuristically_extract_targets(*fn, override_resolve_ctx);
    CHECK(override_result.indirect_annotation_id.has_value());
    if (override_result.indirect_annotation_id)
        CHECK_EQ(*override_result.indirect_annotation_id, site_id);

    auto *site_ann = override_ctx.get_by_id(site_id);
    CHECK(site_ann != nullptr);
    if (site_ann)
    {
        CHECK(site_ann->arg_count.has_value());
        if (site_ann->arg_count)
            CHECK_EQ(*site_ann->arg_count, static_cast<uint8_t>(4));
    }

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

TEST(calling_convention_arg_register_prefix_helper)
{
    const lifted::abi::CallingConvention &cc = lifted::abi::SystemVx64CC::get();
    auto all_regs = cc.getArgRegisters();
    auto no_regs = cc.getArgRegisters(0);
    auto first_two = cc.getArgRegisters(2);
    auto overflow = cc.getArgRegisters(99);

    CHECK_EQ(no_regs.size(), static_cast<size_t>(0));
    CHECK_EQ(first_two.size(), static_cast<size_t>(2));
    if (first_two.size() == 2)
    {
        CHECK_EQ(first_two[0], lifted::abi::ABIRegister::RDI);
        CHECK_EQ(first_two[1], lifted::abi::ABIRegister::RSI);
    }
    CHECK_EQ(overflow.size(), all_regs.size());
}

TEST(lifter_callee_stub_names_distinguish_derived_annotations)
{
    auto discover_binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(discover_binary != nullptr);
    if (!discover_binary)
        return;

    auto info = find_printf_info(*discover_binary);
    CHECK(info.has_value());
    auto entry_va = find_export_va(*discover_binary, "test");
    if (!entry_va)
        entry_va = find_export_va(*discover_binary, "main");
    CHECK(entry_va.has_value());
    if (!info || !entry_va)
        return;

    BinaryContext discover_ctx(std::move(discover_binary));
    llvm::LLVMContext discover_llvm_ctx;
    auto discover_arch = make_x86_64_linux_arch(discover_llvm_ctx);
    CHECK(discover_arch != nullptr);
    if (!discover_arch)
        return;

    auto discover_config = standard_lifter_config_t::from_standard_linux_binary(discover_ctx.binary());
    StandardLifterCallbacks discover_callbacks(discover_config);
    auto discover_lifter_or = Lifter::create(discover_arch.get(), discover_ctx, &discover_callbacks);
    CHECK(static_cast<bool>(discover_lifter_or));
    if (!discover_lifter_or)
    {
        llvm::consumeError(discover_lifter_or.takeError());
        return;
    }

    auto discover_entry_ann = add_entry_annotation(discover_ctx);
    auto discover_result = discover_lifter_or->lift(*entry_va, discover_entry_ann);
    CHECK(static_cast<bool>(discover_result));
    if (!discover_result)
    {
        llvm::consumeError(discover_result.takeError());
        return;
    }

    auto external_sites = collect_external_call_site_rvas(*discover_result);
    CHECK(!external_sites.empty());
    if (external_sites.empty())
        return;
    uint64_t override_site = external_sites.front();

    auto binary = parse_binary(EVAL_IOFILE_SO);
    CHECK(binary != nullptr);
    if (!binary)
        return;
    auto lift_entry_va = find_export_va(*binary, "test");
    if (!lift_entry_va)
        lift_entry_va = find_export_va(*binary, "main");
    CHECK(lift_entry_va.has_value());
    if (!lift_entry_va)
        return;

    BinaryContext bin_ctx(std::move(binary));
    auto direct_addr = find_direct_addr_for_name(bin_ctx, info->base_name);
    CHECK(direct_addr.has_value());
    if (!direct_addr)
        return;

    auto standard_err = import_json(
        bin_ctx,
        "stub-standard",
        R"json({
  "annotations": [
    {"name": "printf", "cc": "systemv_x64", "is_variadic": true, "arg_count": 6}
  ]
})json");
    CHECK(!standard_err);
    if (standard_err)
        return;

    std::string binding_json =
        std::string(R"json({
  "bindings": [
    {"annotation": "printf", "rva": )json") + quoted_hex_string(*direct_addr) +
        std::string(R"json(},
    {"annotation": "printf", "site_rva": )json") + quoted_hex_string(override_site) +
        std::string(R"json(, "override": {"arg_count": 2}}
  ]
})json");
    auto binding_err = import_json(bin_ctx, "stub-binding", binding_json);
    CHECK(!binding_err);
    if (binding_err)
        return;

    auto canonical_id = bin_ctx.get_by_name("printf");
    auto derived_id = bin_ctx.get_site_call(override_site);
    CHECK_NE(canonical_id, INVALID_ANNOTATION_ID);
    CHECK_NE(derived_id, INVALID_ANNOTATION_ID);
    CHECK_NE(derived_id, canonical_id);

    auto *derived_ann = bin_ctx.get_by_id(derived_id);
    CHECK(derived_ann != nullptr);
    if (!derived_ann)
        return;
    std::string expected_derived_name = "printf_" + llvm::utohexstr(override_site);
    CHECK_EQ(derived_ann->name, expected_derived_name);
    CHECK_EQ(bin_ctx.get_by_name(expected_derived_name), INVALID_ANNOTATION_ID);

    llvm::LLVMContext llvm_ctx;
    auto arch = make_x86_64_linux_arch(llvm_ctx);
    CHECK(arch != nullptr);
    if (!arch)
        return;

    auto config = standard_lifter_config_t::from_standard_linux_binary(bin_ctx.binary());
    StandardLifterCallbacks callbacks(config);
    auto lifter_or = Lifter::create(arch.get(), bin_ctx, &callbacks);
    CHECK(static_cast<bool>(lifter_or));
    if (!lifter_or)
    {
        llvm::consumeError(lifter_or.takeError());
        return;
    }

    auto entry_ann = add_entry_annotation(bin_ctx);
    auto result = lifter_or->lift(*lift_entry_va, entry_ann);
    CHECK(static_cast<bool>(result));
    if (!result)
    {
        llvm::consumeError(result.takeError());
        return;
    }

    std::string derived_decl_name = "__lifted_ext_call_" + derived_ann->name;
    auto *derived_decl = result->module->getFunction(derived_decl_name);
    CHECK(derived_decl != nullptr);
    if (external_sites.size() > 1)
    {
        auto *canonical_decl = result->module->getFunction("__lifted_ext_call_printf");
        CHECK(canonical_decl != nullptr);
        if (canonical_decl && derived_decl)
            CHECK_NE(canonical_decl, derived_decl);
    }
}
