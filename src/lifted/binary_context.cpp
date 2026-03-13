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
struct imported_annotation_spec_t
{
    std::unique_ptr<fnc_annotation_t> ann;
    std::vector<std::string>          name_aliases;
    std::optional<uint64_t>           direct_rva;
    std::optional<uint64_t>           dispatcher_rva;
};

llvm::Error make_string_error(const std::string &message)
{
    return llvm::make_error<llvm::StringError>(message, llvm::inconvertibleErrorCode());
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

llvm::Expected<const abi::CallingConvention *> parse_calling_convention(
    const llvm::json::Object &obj,
    const std::string        &path)
{
    auto cc_name_or = parse_optional_string_field(obj, "cc", path);
    if (!cc_name_or)
        return cc_name_or.takeError();
    if (!*cc_name_or)
        return make_string_error(path + ".cc is required");

    if (**cc_name_or == "systemv_x64")
        return &abi::SystemVx64CC::get();
    if (**cc_name_or == "all_regs")
        return &abi::AllRegistersCC::get();

    return make_string_error(path + ".cc has unknown calling convention '" + **cc_name_or + "'");
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
        else if (*read_or)
            param.read = **read_or;

        if (auto written_or = parse_optional_bool_field(*param_obj, "written", path + ".ptr_params." + key);
            !written_or)
            return written_or.takeError();
        else if (*written_or)
            param.written = **written_or;

        if (auto captured_or = parse_optional_bool_field(*param_obj, "captured", path + ".ptr_params." + key);
            !captured_or)
            return captured_or.takeError();
        else if (*captured_or)
            param.captured = **captured_or;

        if (auto fixed_size_or = parse_optional_uint_field(*param_obj, "fixed_size", path + ".ptr_params." + key);
            !fixed_size_or)
            return fixed_size_or.takeError();
        else if (*fixed_size_or)
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
        else if (*sized_by_or)
        {
            auto sized_or = checked_cast_uint<uint32_t>(**sized_by_or,
                                                        path + ".ptr_params." + key + ".sized_by_param_idx");
            if (!sized_or)
                return sized_or.takeError();
            param.sized_by_param_idx = *sized_or;
        }

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
    else if (*fresh_or)
        ret.is_fresh_alloc = **fresh_or;

    if (auto derived_or = parse_optional_uint_field(*ret_obj, "derived_from_param_idx", path + ".ret_ptr");
        !derived_or)
        return derived_or.takeError();
    else if (*derived_or)
    {
        auto idx_or = checked_cast_uint<uint32_t>(**derived_or, path + ".ret_ptr.derived_from_param_idx");
        if (!idx_or)
            return idx_or.takeError();
        ret.derived_from_param_idx = *idx_or;
    }

    return ret;
}

llvm::Expected<imported_annotation_spec_t> parse_imported_annotation(
    const llvm::json::Value &value,
    size_t                   index)
{
    std::string path = "annotations[" + std::to_string(index) + "]";
    auto *obj = value.getAsObject();
    if (!obj)
        return make_string_error(path + " must be an object");

    imported_annotation_spec_t spec;
    spec.ann = std::make_unique<fnc_annotation_t>();

    auto cc_or = parse_calling_convention(*obj, path);
    if (!cc_or)
        return cc_or.takeError();
    spec.ann->cc = *cc_or;

    auto name_or = parse_optional_string_field(*obj, "name", path);
    if (!name_or)
        return name_or.takeError();
    if (*name_or)
        spec.ann->name = **name_or;

    if (auto reads_or = parse_optional_bool_field(*obj, "reads_global_memory", path);
        !reads_or)
        return reads_or.takeError();
    else if (*reads_or)
        spec.ann->reads_global_memory = **reads_or;

    if (auto writes_or = parse_optional_bool_field(*obj, "writes_global_memory", path);
        !writes_or)
        return writes_or.takeError();
    else if (*writes_or)
        spec.ann->writes_global_memory = **writes_or;

    if (auto frees_or = parse_optional_uint_field(*obj, "frees_param_idx", path);
        !frees_or)
        return frees_or.takeError();
    else if (*frees_or)
    {
        auto frees_idx_or = checked_cast_uint<uint32_t>(**frees_or, path + ".frees_param_idx");
        if (!frees_idx_or)
            return frees_idx_or.takeError();
        spec.ann->frees_param_idx = *frees_idx_or;
    }

    auto ptr_params_or = parse_ptr_params(*obj, path);
    if (!ptr_params_or)
        return ptr_params_or.takeError();
    spec.ann->ptr_params = std::move(*ptr_params_or);

    auto ret_ptr_or = parse_ret_ptr(*obj, path);
    if (!ret_ptr_or)
        return ret_ptr_or.takeError();
    spec.ann->ret_ptr = std::move(*ret_ptr_or);

    if (auto ret_size_or = parse_optional_uint_field(*obj, "ret_size_bytes", path);
        !ret_size_or)
        return ret_size_or.takeError();
    else if (*ret_size_or)
    {
        auto ret_size_checked = checked_cast_uint<uint8_t>(**ret_size_or, path + ".ret_size_bytes");
        if (!ret_size_checked)
            return ret_size_checked.takeError();
        spec.ann->ret_size_bytes = *ret_size_checked;
    }

    if (auto volatile_or = parse_optional_bool_field(*obj, "volatile_call", path);
        !volatile_or)
        return volatile_or.takeError();
    else if (*volatile_or)
        spec.ann->volatile_call = **volatile_or;

    if (auto no_return_or = parse_optional_bool_field(*obj, "no_return", path);
        !no_return_or)
        return no_return_or.takeError();
    else if (*no_return_or)
        spec.ann->no_return = **no_return_or;

    auto direct_rva_or = parse_optional_uint_field(*obj, "rva", path);
    if (!direct_rva_or)
        return direct_rva_or.takeError();
    spec.direct_rva = *direct_rva_or;

    auto dispatcher_rva_or = parse_optional_uint_field(*obj, "dispatcher_rva", path);
    if (!dispatcher_rva_or)
        return dispatcher_rva_or.takeError();
    spec.dispatcher_rva = *dispatcher_rva_or;

    if (spec.ann->name.empty() && !spec.direct_rva && !spec.dispatcher_rva)
        return make_string_error(path + " must provide at least one matcher: name, rva, or dispatcher_rva");

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

annotation_id_t BinaryContext::get_indr_call(uint64_t dispatcher_rva) const
{
    for (uint64_t alias : address_aliases(dispatcher_rva))
    {
        auto it = indr_call_annotations_.find(alias);
        if (it != indr_call_annotations_.end())
            return it->second->id;
    }
    return INVALID_ANNOTATION_ID;
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

annotation_id_t BinaryContext::insert(std::unique_ptr<fnc_annotation_t> ann)
{
    assert(ann && "BinaryContext::insert: annotation must be non-null");
    assert(ann->cc && "BinaryContext::insert: annotation must carry a calling convention");

    annotation_id_t id{next_id_raw_++};
    ann->id = id;
    const fnc_annotation_t *raw = ann.get();

    annotations_.emplace(id, std::move(ann));
    if (!raw->name.empty())
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

void BinaryContext::bind_indr_call_alias(const fnc_annotation_t &ann,
                                         uint64_t                dispatcher_rva)
{
    for (uint64_t alias : address_aliases(dispatcher_rva))
        indr_call_annotations_[alias] = &ann;
}

annotation_id_t BinaryContext::create_ext_call(uint64_t dest_rva,
                                               std::unique_ptr<fnc_annotation_t> ann)
{
    annotation_id_t id = insert(std::move(ann));
    const fnc_annotation_t *raw = get_by_id(id);
    bind_ext_call_alias(*raw, dest_rva);
    return id;
}

annotation_id_t BinaryContext::create_indr_call(uint64_t dispatcher_rva,
                                                std::unique_ptr<fnc_annotation_t> ann)
{
    annotation_id_t id = insert(std::move(ann));
    const fnc_annotation_t *raw = get_by_id(id);
    bind_indr_call_alias(*raw, dispatcher_rva);
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

    auto *array = parsed_or_err->getAsArray();
    if (!array)
        return make_string_error("annotation JSON root must be an array");

    std::vector<imported_annotation_spec_t> specs;
    specs.reserve(array->size());

    std::unordered_set<std::string> local_name_keys;
    std::unordered_set<uint64_t>    local_ext_keys;
    std::unordered_set<uint64_t>    local_indr_keys;

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

    auto check_address_keys_available = [&](uint64_t addr,
                                            bool     is_dispatcher) -> llvm::Error
    {
        auto &local_keys = is_dispatcher ? local_indr_keys : local_ext_keys;
        const auto &bound = is_dispatcher ? indr_call_annotations_ : ext_call_annotations_;
        for (uint64_t alias : address_aliases(addr))
        {
            if (bound.count(alias) || local_keys.count(alias))
            {
                std::string kind = is_dispatcher ? "dispatcher_rva" : "rva";
                return make_string_error(
                    "duplicate imported annotation " + kind + " 0x" + llvm::utohexstr(alias));
            }
        }
        for (uint64_t alias : address_aliases(addr))
            local_keys.insert(alias);
        return llvm::Error::success();
    };

    for (size_t i = 0; i < array->size(); ++i)
    {
        auto spec_or = parse_imported_annotation((*array)[i], i);
        if (!spec_or)
            return spec_or.takeError();

        imported_annotation_spec_t spec = std::move(*spec_or);

        if (!spec.ann->name.empty())
        {
            spec.name_aliases.push_back(spec.ann->name);
            if (auto stripped = strip_elf_symbol_version(spec.ann->name))
                if (*stripped != spec.ann->name)
                    spec.name_aliases.push_back(*stripped);

            for (const std::string &alias : spec.name_aliases)
                if (auto err = check_name_key_available(alias))
                    return err;
        }

        if (spec.direct_rva)
            if (auto err = check_address_keys_available(*spec.direct_rva, /*is_dispatcher=*/false))
                return err;

        if (spec.dispatcher_rva)
            if (auto err = check_address_keys_available(*spec.dispatcher_rva, /*is_dispatcher=*/true))
                return err;

        specs.push_back(std::move(spec));
    }

    for (auto &spec : specs)
    {
        annotation_id_t id = insert(std::move(spec.ann));
        const fnc_annotation_t *ann = get_by_id(id);

        for (const std::string &alias : spec.name_aliases)
            if (alias != ann->name)
                bind_name_alias(*ann, alias);

        if (spec.direct_rva)
            bind_ext_call_alias(*ann, *spec.direct_rva);
        if (spec.dispatcher_rva)
            bind_indr_call_alias(*ann, *spec.dispatcher_rva);
    }

    return llvm::Error::success();
}

} // namespace lifted
