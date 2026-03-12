#include "binary_context.hpp"

#include "abi/all_registers_cc.hpp"

#include <cassert>

namespace lifted
{

// ── BinaryContext ─────────────────────────────────────────────────────────────

BinaryContext::BinaryContext(std::unique_ptr<LIEF::Binary> binary)
    : binary_(std::move(binary))
{
    assert(binary_ && "BinaryContext: binary must be non-null");
}

const LIEF::Binary &BinaryContext::binary() const
{
    return *binary_;
}

std::optional<std::string> BinaryContext::symbol_name_at_rva(uint64_t rva) const
{
    auto fmt = binary_->format();

    if (fmt == LIEF::EXE_FORMATS::FORMAT_ELF)
    {
        const auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(binary_.get());
        if (!elf)
            return std::nullopt;

        // LIEF::ELF::Binary::functions() returns all known functions including
        // PLT stubs, with their names and virtual addresses.
        for (const auto &func : elf->functions())
        {
            if (func.address() == rva && !func.name().empty())
                return func.name();
        }

        // Also check dynamic symbols (covers imports not surfaced by functions()).
        for (const auto &sym : elf->dynamic_symbols())
        {
            if (sym.value() == rva && !sym.name().empty())
                return sym.name();
        }

        return std::nullopt;
    }

    if (fmt == LIEF::EXE_FORMATS::FORMAT_PE)
    {
        const auto *pe = dynamic_cast<const LIEF::PE::Binary *>(binary_.get());
        if (!pe)
            return std::nullopt;

        // For PE imports, RVA is the address of the IAT thunk; check symbols.
        for (const auto &sym : pe->symbols())
        {
            if (sym.value() == rva && !sym.name().empty())
                return sym.name();
        }

        return std::nullopt;
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
    auto it = annotations_by_name_.find(name);
    if (it == annotations_by_name_.end())
        return INVALID_ANNOTATION_ID;
    return it->second->id;
}

annotation_id_t BinaryContext::get_ext_call(uint64_t dest_rva) const
{
    auto it = ext_call_annotations_.find(dest_rva);
    if (it == ext_call_annotations_.end())
        return INVALID_ANNOTATION_ID;
    return it->second->id;
}

annotation_id_t BinaryContext::get_indr_call(uint64_t dispatcher_rva) const
{
    auto it = indr_call_annotations_.find(dispatcher_rva);
    if (it == indr_call_annotations_.end())
        return INVALID_ANNOTATION_ID;
    return it->second->id;
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

    if (!ann->name.empty())
        annotations_by_name_[ann->name] = raw;

    annotations_.emplace(id, std::move(ann));
    return id;
}

annotation_id_t BinaryContext::create_ext_call(uint64_t dest_rva,
                                               std::unique_ptr<fnc_annotation_t> ann)
{
    annotation_id_t id = insert(std::move(ann));
    const fnc_annotation_t *raw = get_by_id(id);
    ext_call_annotations_[dest_rva] = raw;
    return id;
}

annotation_id_t BinaryContext::create_indr_call(uint64_t dispatcher_rva,
                                                std::unique_ptr<fnc_annotation_t> ann)
{
    annotation_id_t id = insert(std::move(ann));
    const fnc_annotation_t *raw = get_by_id(id);
    indr_call_annotations_[dispatcher_rva] = raw;
    return id;
}

annotation_id_t BinaryContext::add_annotation(std::unique_ptr<fnc_annotation_t> ann)
{
    return insert(std::move(ann));
}

} // namespace lifted
