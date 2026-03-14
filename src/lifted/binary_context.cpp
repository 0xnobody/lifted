#include "binary_context.hpp"

#include "abi/all_registers_cc.hpp"
#include "abi/systemv_x64.hpp"

#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>

#include <cassert>
#include <limits>
#include <unordered_set>

namespace lifted
{
namespace
{
struct imported_canonical_annotation_spec_t
{
    std::string name;
    std::vector<std::string> name_aliases;
    fnc_annotation_fields_t fields;
};

struct imported_binding_spec_t
{
    std::string annotation_name;
    std::optional<uint64_t> rva;
    std::optional<uint64_t> site_rva;
    std::optional<fnc_annotation_fields_t> override_fields;
};

llvm::Error make_string_error(const std::string &message)
{
    return llvm::make_error<llvm::StringError>(message, llvm::inconvertibleErrorCode());
}

std::optional<std::string> strip_elf_symbol_version_impl(std::string_view name)
{
    if (name.empty())
        return std::nullopt;

    size_t version_pos = name.find("@@");
    size_t version_len = 2;
    if (version_pos == std::string_view::npos)
    {
        version_pos = name.find('@');
        version_len = 1;
        if (version_pos == std::string_view::npos)
            return std::nullopt;

        std::string_view suffix = name.substr(version_pos + version_len);
        if (suffix.empty())
            return std::nullopt;

        bool suffix_all_digits = true;
        for (char ch : suffix)
        {
            if (ch < '0' || ch > '9')
            {
                suffix_all_digits = false;
                break;
            }
        }
        if (suffix_all_digits)
            return std::nullopt;
    }

    if (version_pos == 0)
        return std::nullopt;

    return std::string(name.substr(0, version_pos));
}

llvm::Expected<uint64_t> parse_uint_value(const llvm::json::Value &value,
                                          const std::string       &path)
{
    if (auto u = value.getAsUINT64())
        return *u;

    if (auto i = value.getAsInteger())
    {
        if (*i < 0)
            return make_string_error(path + " must be non-negative");
        return static_cast<uint64_t>(*i);
    }

    if (auto s = value.getAsString())
    {
        uint64_t parsed = 0;
        if (s->getAsInteger(/*Radix=*/0, parsed))
            return make_string_error(path + " must be an integer (decimal or 0x-prefixed hex)");
        return parsed;
    }

    return make_string_error(path + " must be an integer or integer string");
}

llvm::Expected<std::optional<uint64_t>> parse_optional_uint_field(
    const llvm::json::Object &obj,
    llvm::StringRef           key,
    const std::string        &path)
{
    if (const llvm::json::Value *value = obj.get(key))
        return parse_uint_value(*value, path + "." + key.str());
    return std::nullopt;
}

llvm::Expected<std::optional<bool>> parse_optional_bool_field(
    const llvm::json::Object &obj,
    llvm::StringRef           key,
    const std::string        &path)
{
    if (auto value = obj.getBoolean(key))
        return *value;
    if (obj.get(key))
        return make_string_error(path + "." + key.str() + " must be a boolean");
    return std::nullopt;
}

llvm::Expected<std::optional<std::string>> parse_optional_string_field(
    const llvm::json::Object &obj,
    llvm::StringRef           key,
    const std::string        &path)
{
    if (auto value = obj.getString(key))
    {
        if (value->empty())
            return make_string_error(path + "." + key.str() + " must not be empty");
        return value->str();
    }
    if (obj.get(key))
        return make_string_error(path + "." + key.str() + " must be a string");
    return std::nullopt;
}

template <typename T>
llvm::Expected<T> checked_cast_uint(uint64_t value,
                                    const std::string &path)
{
    if (value > static_cast<uint64_t>(std::numeric_limits<T>::max()))
        return make_string_error(path + " is out of range");
    return static_cast<T>(value);
}

llvm::Expected<const abi::CallingConvention *> parse_calling_convention_name(
    llvm::StringRef       cc_name,
    const std::string    &path)
{
    if (cc_name == "systemv_x64")
        return &abi::SystemVx64CC::get();
    if (cc_name == "all_regs")
        return &abi::AllRegistersCC::get();
    return make_string_error(path + " has unknown calling convention '" + cc_name.str() + "'");
}

bool key_is_allowed(llvm::StringRef key,
                    std::initializer_list<llvm::StringRef> allowed)
{
    for (llvm::StringRef candidate : allowed)
        if (key == candidate)
            return true;
    return false;
}

llvm::Error reject_unknown_keys(const llvm::json::Object         &obj,
                                const std::string                &path,
                                std::initializer_list<llvm::StringRef> allowed)
{
    for (const auto &entry : obj)
        if (!key_is_allowed(entry.first, allowed))
            return make_string_error(path + " has unknown key '" + llvm::StringRef(entry.first).str() + "'");
    return llvm::Error::success();
}

llvm::Expected<std::unordered_map<uint32_t, ptr_param_t>> parse_ptr_params(
    const llvm::json::Object &obj,
    const std::string        &path)
{
    std::unordered_map<uint32_t, ptr_param_t> result;

    const llvm::json::Object *ptr_params_obj = obj.getObject("ptr_params");
    if (!ptr_params_obj)
    {
        if (obj.get("ptr_params"))
            return make_string_error(path + ".ptr_params must be an object");
        return result;
    }

    for (const auto &entry : *ptr_params_obj)
    {
        std::string key = llvm::StringRef(entry.first).str();
        uint64_t    param_idx_raw = 0;
        if (llvm::StringRef(key).getAsInteger(/*Radix=*/0, param_idx_raw))
            return make_string_error(path + ".ptr_params key '" + key + "' must be an integer");

        auto param_idx_or = checked_cast_uint<uint32_t>(param_idx_raw,
                                                        path + ".ptr_params." + key);
        if (!param_idx_or)
            return param_idx_or.takeError();

        auto *param_obj = entry.second.getAsObject();
        if (!param_obj)
            return make_string_error(path + ".ptr_params." + key + " must be an object");

        ptr_param_t param{
            .read = false,
            .written = false,
            .captured = false,
            .fixed_size = std::nullopt,
            .sized_by_param_idx = std::nullopt,
        };

        if (auto read_or = parse_optional_bool_field(*param_obj, "read", path + ".ptr_params." + key);
            !read_or)
            return read_or.takeError();
        else if (read_or->has_value())
            param.read = **read_or;

        if (auto written_or = parse_optional_bool_field(*param_obj, "written", path + ".ptr_params." + key);
            !written_or)
            return written_or.takeError();
        else if (written_or->has_value())
            param.written = **written_or;

        if (auto captured_or = parse_optional_bool_field(*param_obj, "captured", path + ".ptr_params." + key);
            !captured_or)
            return captured_or.takeError();
        else if (captured_or->has_value())
            param.captured = **captured_or;

        if (auto fixed_size_or = parse_optional_uint_field(*param_obj, "fixed_size", path + ".ptr_params." + key);
            !fixed_size_or)
            return fixed_size_or.takeError();
        else if (fixed_size_or->has_value())
        {
            auto fixed_or = checked_cast_uint<size_t>(**fixed_size_or,
                                                      path + ".ptr_params." + key + ".fixed_size");
            if (!fixed_or)
                return fixed_or.takeError();
            param.fixed_size = *fixed_or;
        }

        if (auto sized_by_or = parse_optional_uint_field(*param_obj, "sized_by_param_idx", path + ".ptr_params." + key);
            !sized_by_or)
            return sized_by_or.takeError();
        else if (sized_by_or->has_value())
        {
            auto sized_or = checked_cast_uint<uint32_t>(**sized_by_or,
                                                        path + ".ptr_params." + key + ".sized_by_param_idx");
            if (!sized_or)
                return sized_or.takeError();
            param.sized_by_param_idx = *sized_or;
        }

        result[*param_idx_or] = param;

        result[*param_idx_or] = param;
    }

    return result;
}

llvm::Expected<std::optional<ret_ptr_t>> parse_ret_ptr(
    const llvm::json::Object &obj,
    const std::string        &path)
{
    const llvm::json::Object *ret_obj = obj.getObject("ret_ptr");
    if (!ret_obj)
    {
        if (obj.get("ret_ptr"))
            return make_string_error(path + ".ret_ptr must be an object");
        return std::nullopt;
    }

    ret_ptr_t ret{
        .is_fresh_alloc = false,
        .derived_from_param_idx = std::nullopt,
    };

    if (auto fresh_or = parse_optional_bool_field(*ret_obj, "is_fresh_alloc", path + ".ret_ptr");
        !fresh_or)
        return fresh_or.takeError();
    else if (fresh_or->has_value())
        ret.is_fresh_alloc = **fresh_or;

    if (auto derived_or = parse_optional_uint_field(*ret_obj, "derived_from_param_idx", path + ".ret_ptr");
        !derived_or)
        return derived_or.takeError();
    else if (derived_or->has_value())
    {
        auto idx_or = checked_cast_uint<uint32_t>(**derived_or, path + ".ret_ptr.derived_from_param_idx");
        if (!idx_or)
            return idx_or.takeError();
        ret.derived_from_param_idx = *idx_or;
    }

    return ret;
}

llvm::Expected<fnc_annotation_fields_t> parse_annotation_fields(
    const llvm::json::Object &obj,
    const std::string        &path)
{
    fnc_annotation_fields_t fields;

    if (auto cc_name_or = parse_optional_string_field(obj, "cc", path); !cc_name_or)
        return cc_name_or.takeError();
    else if (cc_name_or->has_value())
    {
        auto cc_or = parse_calling_convention_name(**cc_name_or, path + ".cc");
        if (!cc_or)
            return cc_or.takeError();
        fields.cc = *cc_or;
    }

    if (auto reads_or = parse_optional_bool_field(obj, "reads_global_memory", path); !reads_or)
        return reads_or.takeError();
    else if (reads_or->has_value())
        fields.reads_global_memory = **reads_or;

    if (auto writes_or = parse_optional_bool_field(obj, "writes_global_memory", path); !writes_or)
        return writes_or.takeError();
    else if (writes_or->has_value())
        fields.writes_global_memory = **writes_or;

    if (auto frees_or = parse_optional_uint_field(obj, "frees_param_idx", path); !frees_or)
        return frees_or.takeError();
    else if (frees_or->has_value())
    {
        auto frees_idx_or = checked_cast_uint<uint32_t>(**frees_or, path + ".frees_param_idx");
        if (!frees_idx_or)
            return frees_idx_or.takeError();
        fields.frees_param_idx = *frees_idx_or;
    }

    auto ptr_params_or = parse_ptr_params(obj, path);
    if (!ptr_params_or)
        return ptr_params_or.takeError();
    if (obj.get("ptr_params"))
        fields.ptr_params = std::move(*ptr_params_or);

    auto ret_ptr_or = parse_ret_ptr(obj, path);
    if (!ret_ptr_or)
        return ret_ptr_or.takeError();
    if (obj.get("ret_ptr"))
        fields.ret_ptr = std::move(**ret_ptr_or);

    if (auto ret_size_or = parse_optional_uint_field(obj, "ret_size_bytes", path); !ret_size_or)
        return ret_size_or.takeError();
    else if (ret_size_or->has_value())
    {
        auto ret_size_checked = checked_cast_uint<uint8_t>(**ret_size_or, path + ".ret_size_bytes");
        if (!ret_size_checked)
            return ret_size_checked.takeError();
        fields.ret_size_bytes = *ret_size_checked;
    }

    if (auto volatile_or = parse_optional_bool_field(obj, "volatile_call", path); !volatile_or)
        return volatile_or.takeError();
    else if (volatile_or->has_value())
        fields.volatile_call = **volatile_or;

    if (auto no_return_or = parse_optional_bool_field(obj, "no_return", path); !no_return_or)
        return no_return_or.takeError();
    else if (no_return_or->has_value())
        fields.no_return = **no_return_or;

    if (auto variadic_or = parse_optional_bool_field(obj, "is_variadic", path); !variadic_or)
        return variadic_or.takeError();
    else if (variadic_or->has_value())
        fields.is_variadic = **variadic_or;

    if (auto arg_count_or = parse_optional_uint_field(obj, "arg_count", path); !arg_count_or)
        return arg_count_or.takeError();
    else if (arg_count_or->has_value())
    {
        auto checked = checked_cast_uint<uint8_t>(**arg_count_or, path + ".arg_count");
        if (!checked)
            return checked.takeError();
        fields.arg_count = *checked;
    }

    return fields;

    return fields;
}

bool annotation_fields_present(const fnc_annotation_fields_t &fields)
{
    return fields.cc.has_value() ||
           fields.reads_global_memory.has_value() ||
           fields.writes_global_memory.has_value() ||
           fields.frees_param_idx.has_value() ||
           fields.ptr_params.has_value() ||
           fields.ret_ptr.has_value() ||
           fields.ret_size_bytes.has_value() ||
           fields.volatile_call.has_value() ||
           fields.no_return.has_value() ||
           fields.is_variadic.has_value() ||
           fields.arg_count.has_value();
}

void apply_annotation_fields(fnc_annotation_t               &ann,
                             const fnc_annotation_fields_t &fields)
{
    if (fields.cc.has_value())
        ann.cc = *fields.cc;
    if (fields.reads_global_memory.has_value())
        ann.reads_global_memory = *fields.reads_global_memory;
    if (fields.writes_global_memory.has_value())
        ann.writes_global_memory = *fields.writes_global_memory;
    if (fields.frees_param_idx.has_value())
        ann.frees_param_idx = *fields.frees_param_idx;
    if (fields.ptr_params.has_value())
        ann.ptr_params = *fields.ptr_params;
    if (fields.ret_ptr.has_value())
        ann.ret_ptr = *fields.ret_ptr;
    if (fields.ret_size_bytes.has_value())
        ann.ret_size_bytes = *fields.ret_size_bytes;
    if (fields.volatile_call.has_value())
        ann.volatile_call = *fields.volatile_call;
    if (fields.no_return.has_value())
        ann.no_return = *fields.no_return;
    if (fields.is_variadic.has_value())
        ann.is_variadic = *fields.is_variadic;
    if (fields.arg_count.has_value())
        ann.arg_count = *fields.arg_count;
}

llvm::Expected<fnc_annotation_t> materialize_annotation(
    std::string                  name,
    const fnc_annotation_fields_t &fields)
{
    if (!fields.cc)
        return make_string_error("annotation '" + name + "' must provide a calling convention");

    fnc_annotation_t ann;
    ann.name = std::move(name);
    ann.cc = *fields.cc;
    apply_annotation_fields(ann, fields);
    return ann;
}

llvm::Expected<fnc_annotation_t> materialize_annotation(
    const fnc_annotation_t      &base,
    const fnc_annotation_fields_t &override_fields)
{
    fnc_annotation_t ann = base;
    apply_annotation_fields(ann, override_fields);
    if (!ann.cc)
        return make_string_error("derived annotation for '" + base.name + "' is missing a calling convention");
    return ann;
}

llvm::Expected<imported_canonical_annotation_spec_t> parse_imported_canonical_annotation(
    const llvm::json::Value &value,
    size_t                   index)
{
    std::string path = "annotations[" + std::to_string(index) + "]";
    auto *obj = value.getAsObject();
    if (!obj)
        return make_string_error(path + " must be an object");

    if (auto err = reject_unknown_keys(
            *obj,
            path,
            {"name",
             "cc",
             "reads_global_memory",
             "writes_global_memory",
             "frees_param_idx",
             "ptr_params",
             "ret_ptr",
             "ret_size_bytes",
             "volatile_call",
             "no_return",
             "is_variadic",
             "arg_count"});
        err)
        return std::move(err);

    auto name_or = parse_optional_string_field(*obj, "name", path);
    if (!name_or)
        return name_or.takeError();
    if (!*name_or)
        return make_string_error(path + ".name is required");

    auto fields_or = parse_annotation_fields(*obj, path);
    if (!fields_or)
        return fields_or.takeError();

    imported_canonical_annotation_spec_t spec;
    spec.name = std::move(**name_or);
    spec.fields = std::move(*fields_or);
    spec.name_aliases.push_back(spec.name);
    if (auto stripped = strip_elf_symbol_version_impl(spec.name))
        if (*stripped != spec.name)
            spec.name_aliases.push_back(*stripped);
    return spec;
}

llvm::Expected<imported_binding_spec_t> parse_imported_binding(
    const llvm::json::Value &value,
    size_t                   index)
{
    std::string path = "bindings[" + std::to_string(index) + "]";
    auto *obj = value.getAsObject();
    if (!obj)
        return make_string_error(path + " must be an object");

    if (auto err = reject_unknown_keys(*obj, path, {"annotation", "rva", "site_rva", "override"}); err)
        return std::move(err);

    auto annotation_name_or = parse_optional_string_field(*obj, "annotation", path);
    if (!annotation_name_or)
        return annotation_name_or.takeError();
    if (!*annotation_name_or)
        return make_string_error(path + ".annotation is required");

    auto rva_or = parse_optional_uint_field(*obj, "rva", path);
    if (!rva_or)
        return rva_or.takeError();

    auto site_rva_or = parse_optional_uint_field(*obj, "site_rva", path);
    if (!site_rva_or)
        return site_rva_or.takeError();

    if (static_cast<bool>(*rva_or) == static_cast<bool>(*site_rva_or))
        return make_string_error(path + " must provide exactly one matcher: rva or site_rva");

    imported_binding_spec_t spec;
    spec.annotation_name = std::move(**annotation_name_or);
    spec.rva = *rva_or;
    spec.site_rva = *site_rva_or;

    if (const llvm::json::Value *override_value = obj->get("override"))
    {
        auto *override_obj = override_value->getAsObject();
        if (!override_obj)
            return make_string_error(path + ".override must be an object");

        if (auto err = reject_unknown_keys(
                *override_obj,
                path + ".override",
                {"cc",
                 "reads_global_memory",
                 "writes_global_memory",
                 "frees_param_idx",
                 "ptr_params",
                 "ret_ptr",
                 "ret_size_bytes",
                 "volatile_call",
                 "no_return",
                 "is_variadic",
                 "arg_count"});
            err)
            return std::move(err);

        auto override_fields_or = parse_annotation_fields(*override_obj, path + ".override");
        if (!override_fields_or)
            return override_fields_or.takeError();
        if (annotation_fields_present(*override_fields_or))
            spec.override_fields = std::move(*override_fields_or);
    }

    return spec;
}
} // namespace

// ── BinaryContext ─────────────────────────────────────────────────────────────

BinaryContext::BinaryContext(std::unique_ptr<LIEF::Binary> binary)
    : binary_(std::move(binary))
{
    assert(binary_ && "BinaryContext: binary must be non-null");
    index_binary_metadata();
}

const LIEF::Binary &BinaryContext::binary() const
{
    return *binary_;
}

std::vector<uint64_t> BinaryContext::address_aliases(uint64_t addr) const
{
    std::vector<uint64_t> aliases;
    aliases.push_back(addr);

    const uint64_t imagebase = binary_->imagebase();
    if (imagebase == 0)
        return aliases;

    auto push_unique = [&aliases](uint64_t candidate)
    {
        for (uint64_t existing : aliases)
            if (existing == candidate)
                return;
        aliases.push_back(candidate);
    };

    if (addr >= imagebase)
        push_unique(addr - imagebase);
    if (addr <= std::numeric_limits<uint64_t>::max() - imagebase)
        push_unique(addr + imagebase);
    return aliases;
}

std::optional<std::string> BinaryContext::strip_elf_symbol_version(std::string_view name)
{
	return strip_elf_symbol_version_impl(name);
}

void BinaryContext::index_direct_target_name(uint64_t         addr,
                                             std::string_view name,
                                             bool             overwrite)
{
    if (name.empty())
        return;

    for (uint64_t alias : address_aliases(addr))
    {
        auto it = direct_target_names_.find(alias);
        if (it == direct_target_names_.end())
        {
            direct_target_names_.emplace(alias, std::string(name));
            continue;
        }
        if (overwrite)
            it->second = std::string(name);
    }
}

void BinaryContext::index_import_slot_name(uint64_t         addr,
                                           std::string_view name,
                                           bool             overwrite)
{
    if (name.empty())
        return;

    for (uint64_t alias : address_aliases(addr))
    {
        auto it = import_slot_names_.find(alias);
        if (it == import_slot_names_.end())
        {
            import_slot_names_.emplace(alias, std::string(name));
            continue;
        }
        if (overwrite)
            it->second = std::string(name);
    }
}

void BinaryContext::index_binary_metadata()
{
    for (const auto &func : binary_->imported_functions())
        index_direct_target_name(func.address(), func.name(), /*overwrite=*/true);

    for (const auto &func : binary_->exported_functions())
        index_direct_target_name(func.address(), func.name());

    switch (binary_->format())
    {
    case LIEF::EXE_FORMATS::FORMAT_ELF:
    {
        const auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(binary_.get());
        if (!elf)
            break;

        for (const auto &func : elf->functions())
            index_direct_target_name(func.address(), func.name());

        for (const auto &sym : elf->dynamic_symbols())
            index_direct_target_name(sym.value(), sym.name());

        const auto *plt_sec = elf->get_section(".plt.sec");
        const auto *plt = plt_sec ? nullptr : elf->get_section(".plt");
        uint64_t plt_stub_base = 0;
        if (plt_sec)
            plt_stub_base = plt_sec->virtual_address();
        else if (plt)
            plt_stub_base = plt->virtual_address() + 0x10;

        size_t plt_index = 0;
        for (const auto &reloc : elf->pltgot_relocations())
        {
            if (!reloc.has_symbol() || !reloc.symbol())
                continue;

            llvm::StringRef import_name = reloc.symbol()->name();
            index_import_slot_name(reloc.address(), import_name, /*overwrite=*/true);
            if (plt_stub_base != 0)
                index_direct_target_name(plt_stub_base + plt_index * 0x10, import_name, /*overwrite=*/true);
            ++plt_index;
        }

        for (const auto &reloc : elf->dynamic_relocations())
            if (reloc.has_symbol() && reloc.symbol())
                index_import_slot_name(reloc.address(), reloc.symbol()->name());
        break;
    }
    case LIEF::EXE_FORMATS::FORMAT_PE:
    {
        const auto *pe = dynamic_cast<const LIEF::PE::Binary *>(binary_.get());
        if (!pe)
            break;

        for (const auto &sym : pe->symbols())
            index_direct_target_name(sym.value(), sym.name());

        for (const auto &import : pe->imports())
        {
            for (const auto &entry : import.entries())
            {
                index_import_slot_name(entry.iat_address(), entry.name(), /*overwrite=*/true);
                index_direct_target_name(entry.iat_address(), entry.name());
            }
        }

        for (const auto &import : pe->delay_imports())
        {
            for (const auto &entry : import.entries())
            {
                index_import_slot_name(entry.value(), entry.name());
                index_direct_target_name(entry.value(), entry.name());
            }
        }
        break;
    }
    default:
        break;
    }
}

std::optional<std::string> BinaryContext::symbol_name_at_rva(uint64_t rva) const
{
    for (uint64_t alias : address_aliases(rva))
    {
        auto it = direct_target_names_.find(alias);
        if (it != direct_target_names_.end())
            return it->second;
    }
    return std::nullopt;
}

std::optional<std::string> BinaryContext::import_name_for_slot(uint64_t slot_rva) const
{
    for (uint64_t alias : address_aliases(slot_rva))
    {
        auto it = import_slot_names_.find(alias);
        if (it != import_slot_names_.end())
            return it->second;
    }
    return std::nullopt;
}

// ── Lookups ───────────────────────────────────────────────────────────────────

const fnc_annotation_t *BinaryContext::get_by_id(annotation_id_t id) const
{
    auto it = annotations_.find(id);
    if (it == annotations_.end())
        return nullptr;
    return it->second.get();
}

annotation_id_t BinaryContext::get_by_name(const std::string &name) const
{
    if (auto it = annotations_by_name_.find(name); it != annotations_by_name_.end())
        return it->second->id;

    if (auto stripped = strip_elf_symbol_version(name))
    {
        auto it = annotations_by_name_.find(*stripped);
        if (it != annotations_by_name_.end())
            return it->second->id;
    }

    return INVALID_ANNOTATION_ID;
}

annotation_id_t BinaryContext::get_ext_call(uint64_t dest_rva) const
{
    for (uint64_t alias : address_aliases(dest_rva))
    {
        auto it = ext_call_annotations_.find(alias);
        if (it != ext_call_annotations_.end())
            return it->second->id;
    }
    return INVALID_ANNOTATION_ID;
}

annotation_id_t BinaryContext::get_site_call(uint64_t site_rva) const
{
    for (uint64_t alias : address_aliases(site_rva))
    {
        auto it = site_annotations_.find(alias);
        if (it != site_annotations_.end())
            return it->second->id;
    }
    return INVALID_ANNOTATION_ID;
}

annotation_id_t BinaryContext::resolve_direct_call_annotation(
    uint64_t                        caller_site_rva,
    uint64_t                        dest_rva,
    std::optional<std::string_view> resolved_name,
    const abi::CallingConvention   &fallback_cc)
{
    if (auto anno_id = get_site_call(caller_site_rva); anno_id != INVALID_ANNOTATION_ID)
        return anno_id;

    if (auto anno_id = get_ext_call(dest_rva); anno_id != INVALID_ANNOTATION_ID)
        return anno_id;

    if (resolved_name)
    {
        if (auto anno_id = get_by_name(std::string(*resolved_name)); anno_id != INVALID_ANNOTATION_ID)
            return anno_id;
    }

    fnc_annotation_fields_t fields;
    fields.cc = &fallback_cc;

    auto materialized_or = materialize_annotation(
        resolved_name ? std::string(*resolved_name) : "ext_auto_" + llvm::utohexstr(dest_rva),
        fields);
    assert(materialized_or && "BinaryContext fallback direct annotation must materialize");
    return create_ext_call(dest_rva, std::make_unique<fnc_annotation_t>(std::move(*materialized_or)));
}

annotation_id_t BinaryContext::resolve_indirect_call_annotation(
    uint64_t                        caller_site_rva,
    std::optional<std::string_view> import_name,
    const abi::CallingConvention   &fallback_cc)
{
    if (auto anno_id = get_site_call(caller_site_rva); anno_id != INVALID_ANNOTATION_ID)
        return anno_id;

    if (import_name)
    {
        if (auto anno_id = get_by_name(std::string(*import_name)); anno_id != INVALID_ANNOTATION_ID)
            return anno_id;
    }

    fnc_annotation_fields_t fields;
    fields.cc = &fallback_cc;

    auto materialized_or = materialize_annotation(
        import_name ? std::string(*import_name) : "indr_dispatch_" + llvm::utohexstr(caller_site_rva),
        fields);
    assert(materialized_or && "BinaryContext fallback indirect annotation must materialize");
    return create_site_call(caller_site_rva, std::make_unique<fnc_annotation_t>(std::move(*materialized_or)));
}

annotation_id_t BinaryContext::get_or_create_builtin_annotation(
    builtin_annotation_kind_t kind)
{
    if (auto it = builtin_annotation_ids_.find(kind); it != builtin_annotation_ids_.end())
        return it->second;

    auto ann = std::make_unique<fnc_annotation_t>();
    switch (kind)
    {
    case builtin_annotation_kind_t::lifted_core_all_registers:
        ann->name = "__lifted_builtin_all_regs_core";
        ann->cc = &abi::AllRegistersCC::get();
        break;
    case builtin_annotation_kind_t::lifted_observer_all_registers:
        ann->name = "__lifted_builtin_all_regs_observer";
        ann->cc = &abi::AllRegistersCC::get();
        break;
    }

    annotation_id_t id = insert(std::move(ann));
    builtin_annotation_ids_[kind] = id;
    return id;
}

// ── Creation ──────────────────────────────────────────────────────────────────

annotation_id_t BinaryContext::insert(std::unique_ptr<fnc_annotation_t> ann,
                                      bool                              index_name)
{
    assert(ann && "BinaryContext::insert: annotation must be non-null");
    assert(ann->cc && "BinaryContext::insert: annotation must carry a calling convention");

    annotation_id_t id{next_id_raw_++};
    ann->id = id;
    const fnc_annotation_t *raw = ann.get();

    annotations_.emplace(id, std::move(ann));
    if (index_name && !raw->name.empty())
        bind_name_alias(*raw, raw->name);
    return id;
}

void BinaryContext::bind_name_alias(const fnc_annotation_t &ann,
                                    std::string_view        name)
{
    if (name.empty())
        return;
    annotations_by_name_[std::string(name)] = &ann;
}

void BinaryContext::bind_ext_call_alias(const fnc_annotation_t &ann,
                                        uint64_t                dest_rva)
{
    for (uint64_t alias : address_aliases(dest_rva))
        ext_call_annotations_[alias] = &ann;
}

void BinaryContext::bind_site_alias(const fnc_annotation_t &ann,
                                    uint64_t                site_rva)
{
    for (uint64_t alias : address_aliases(site_rva))
        site_annotations_[alias] = &ann;
}

annotation_id_t BinaryContext::create_ext_call(uint64_t dest_rva,
                                               std::unique_ptr<fnc_annotation_t> ann)
{
    annotation_id_t id = insert(std::move(ann));
    const fnc_annotation_t *raw = get_by_id(id);
    bind_ext_call_alias(*raw, dest_rva);
    return id;
}

annotation_id_t BinaryContext::create_site_call(uint64_t site_rva,
                                                std::unique_ptr<fnc_annotation_t> ann)
{
    annotation_id_t id = insert(std::move(ann));
    const fnc_annotation_t *raw = get_by_id(id);
    bind_site_alias(*raw, site_rva);
    return id;
}

annotation_id_t BinaryContext::add_annotation(std::unique_ptr<fnc_annotation_t> ann)
{
    return insert(std::move(ann));
}

llvm::Error BinaryContext::import_annotations_from_json(std::filesystem::path path)
{
    auto buffer_or_err = llvm::MemoryBuffer::getFile(path.string());
    if (!buffer_or_err)
        return llvm::errorCodeToError(buffer_or_err.getError());

    auto parsed_or_err = llvm::json::parse(buffer_or_err.get()->getBuffer());
    if (!parsed_or_err)
        return parsed_or_err.takeError();

    auto *root = parsed_or_err->getAsObject();
    if (!root)
        return make_string_error("annotation JSON root must be an object");

    if (auto err = reject_unknown_keys(*root, "root", {"annotations", "bindings"}); err)
        return err;

    const llvm::json::Array *annotations_array = root->getArray("annotations");
    if (!annotations_array && root->get("annotations"))
        return make_string_error("root.annotations must be an array");

    const llvm::json::Array *bindings_array = root->getArray("bindings");
    if (!bindings_array && root->get("bindings"))
        return make_string_error("root.bindings must be an array");

    if (!annotations_array && !bindings_array)
        return make_string_error("annotation JSON root must contain 'annotations' and/or 'bindings'");

    std::vector<imported_canonical_annotation_spec_t> annotation_specs;
    std::vector<imported_binding_spec_t>              binding_specs;
    if (annotations_array)
        annotation_specs.reserve(annotations_array->size());
    if (bindings_array)
        binding_specs.reserve(bindings_array->size());

    std::unordered_set<std::string> local_name_keys;
    std::unordered_set<uint64_t>    local_ext_keys;
    std::unordered_set<uint64_t>    local_site_keys;

    auto check_name_key_available = [&](std::string_view name) -> llvm::Error
    {
        if (name.empty())
            return llvm::Error::success();

        std::string key(name);
        if (annotations_by_name_.count(key) || local_name_keys.count(key))
            return make_string_error("duplicate imported annotation name/alias '" + key + "'");
        local_name_keys.insert(std::move(key));
        return llvm::Error::success();
    };

    auto check_address_key_available = [&](uint64_t addr,
                                           bool     is_site) -> llvm::Error
    {
        auto &local_keys = is_site ? local_site_keys : local_ext_keys;
        const auto &bound = is_site ? site_annotations_ : ext_call_annotations_;
        for (uint64_t alias : address_aliases(addr))
        {
            if (bound.count(alias) || local_keys.count(alias))
            {
                std::string kind = is_site ? "site_rva" : "rva";
                return make_string_error(
                    "duplicate imported annotation " + kind + " 0x" + llvm::utohexstr(alias));
            }
        }
        for (uint64_t alias : address_aliases(addr))
            local_keys.insert(alias);
        return llvm::Error::success();
    };

    if (annotations_array)
    {
        for (size_t i = 0; i < annotations_array->size(); ++i)
        {
            auto spec_or = parse_imported_canonical_annotation((*annotations_array)[i], i);
            if (!spec_or)
                return spec_or.takeError();

            for (const std::string &alias : spec_or->name_aliases)
                if (auto err = check_name_key_available(alias))
                    return err;

            annotation_specs.push_back(std::move(*spec_or));
        }
    }

    if (bindings_array)
    {
        for (size_t i = 0; i < bindings_array->size(); ++i)
        {
            auto spec_or = parse_imported_binding((*bindings_array)[i], i);
            if (!spec_or)
                return spec_or.takeError();

            if (spec_or->rva)
                if (auto err = check_address_key_available(*spec_or->rva, /*is_site=*/false))
                    return err;
            if (spec_or->site_rva)
                if (auto err = check_address_key_available(*spec_or->site_rva, /*is_site=*/true))
                    return err;

            binding_specs.push_back(std::move(*spec_or));
        }
    }

    auto binding_target_exists = [&](std::string_view annotation_name)
    {
        if (get_by_name(std::string(annotation_name)) != INVALID_ANNOTATION_ID)
            return true;
        if (local_name_keys.count(std::string(annotation_name)) > 0)
            return true;
        if (auto stripped = strip_elf_symbol_version_impl(annotation_name))
            return local_name_keys.count(*stripped) > 0;
        return false;
    };

    std::unordered_set<std::string> local_derived_names;
    auto derived_annotation_name_exists = [&](std::string_view candidate)
    {
        std::string key(candidate);
        if (local_name_keys.count(key) > 0 || local_derived_names.count(key) > 0)
            return true;
        for (const auto &[id, ann] : annotations_)
            if (ann && ann->name == candidate)
                return true;
        return false;
    };

    auto make_derived_binding_name = [&](const fnc_annotation_t      &base,
                                         const imported_binding_spec_t &spec)
    {
        uint64_t binding_rva = spec.site_rva ? *spec.site_rva : *spec.rva;
        std::string candidate = (base.name.empty() ? "ann" : base.name) +
                                "_" + llvm::utohexstr(binding_rva);
        if (!derived_annotation_name_exists(candidate))
            return candidate;

        std::string disambiguated = candidate + (spec.site_rva ? "_site" : "_rva");
        if (!derived_annotation_name_exists(disambiguated))
            return disambiguated;

        unsigned suffix = 2;
        while (derived_annotation_name_exists(disambiguated + "_" + std::to_string(suffix)))
            ++suffix;
        return disambiguated + "_" + std::to_string(suffix);
    };

    for (const auto &spec : binding_specs)
        if (!binding_target_exists(spec.annotation_name))
            return make_string_error("binding references unknown annotation '" + spec.annotation_name + "'");

    for (auto &spec : annotation_specs)
    {
        auto materialized_or = materialize_annotation(spec.name, spec.fields);
        if (!materialized_or)
            return materialized_or.takeError();

        annotation_id_t id = insert(std::make_unique<fnc_annotation_t>(std::move(*materialized_or)));
        const fnc_annotation_t *ann = get_by_id(id);
        for (const std::string &alias : spec.name_aliases)
            if (alias != ann->name)
                bind_name_alias(*ann, alias);
    }

    for (auto &spec : binding_specs)
    {
        annotation_id_t base_id = get_by_name(spec.annotation_name);
        if (base_id == INVALID_ANNOTATION_ID)
            return make_string_error("binding references unknown annotation '" + spec.annotation_name + "'");
        const fnc_annotation_t *bound_ann = get_by_id(base_id);
        if (!bound_ann)
            return make_string_error("binding resolved missing annotation id for '" + spec.annotation_name + "'");

        if (spec.override_fields)
        {
            auto derived_or = materialize_annotation(*bound_ann, *spec.override_fields);
            if (!derived_or)
                return derived_or.takeError();
            derived_or->name = make_derived_binding_name(*bound_ann, spec);
            local_derived_names.insert(derived_or->name);
            annotation_id_t derived_id = insert(
                std::make_unique<fnc_annotation_t>(std::move(*derived_or)),
                /*index_name=*/false);
            bound_ann = get_by_id(derived_id);
        }

        if (spec.rva)
            bind_ext_call_alias(*bound_ann, *spec.rva);
        if (spec.site_rva)
            bind_site_alias(*bound_ann, *spec.site_rva);
    }

    return llvm::Error::success();
}

} // namespace lifted
