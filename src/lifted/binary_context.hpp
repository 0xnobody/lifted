#pragma once

#include "compat/lief_compat.hpp"

#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace llvm
{
class Error;
}

namespace lifted::abi
{
class CallingConvention;
} // namespace lifted::abi

namespace lifted
{

// ── annotation_id_t ──────────────────────────────────────────────────────────

/// Strongly typed annotation identifier — cannot be accidentally passed as a
/// dest/site RVA.
struct annotation_id_t
{
    uint64_t value = UINT64_MAX;

    bool operator==(const annotation_id_t &) const = default;
    bool operator!=(const annotation_id_t &) const = default;
    bool operator<(const annotation_id_t &o) const noexcept { return value < o.value; }
    bool valid() const noexcept { return value != UINT64_MAX; }
};

inline constexpr annotation_id_t INVALID_ANNOTATION_ID{UINT64_MAX};

} // namespace lifted

// std::hash specialisation so annotation_id_t works as unordered_map key.
template <>
struct std::hash<lifted::annotation_id_t>
{
    size_t operator()(const lifted::annotation_id_t &id) const noexcept
    {
        return std::hash<uint64_t>{}(id.value);
    }
};

namespace lifted
{

// ── ptr_param_t ──────────────────────────────────────────────────────────────

struct ptr_param_t
{
    bool read;
    bool written;
    bool captured;
    std::optional<size_t> fixed_size;
    std::optional<uint32_t> sized_by_param_idx;
};

// ── ret_ptr_t ─────────────────────────────────────────────────────────────────

struct ret_ptr_t
{
    bool is_fresh_alloc;
    std::optional<uint32_t> derived_from_param_idx;
};

// ── fnc_annotation_fields_t ──────────────────────────────────────────────────

/// Sparse authoring surface shared by canonical annotation definitions and
/// binding-local overrides. Missing fields inherit pessimistic defaults during
/// canonical materialization or preserve the base value during override
/// materialization.
struct fnc_annotation_fields_t
{
    std::optional<const abi::CallingConvention *> cc;
    std::optional<bool> reads_global_memory;
    std::optional<bool> writes_global_memory;
    std::optional<uint32_t> frees_param_idx;
    std::optional<std::unordered_map<uint32_t, ptr_param_t>> ptr_params;
    std::optional<ret_ptr_t> ret_ptr;
    std::optional<uint8_t> ret_size_bytes;
    std::optional<bool> volatile_call;
    std::optional<bool> no_return;
    std::optional<bool> is_variadic;
    std::optional<uint8_t> arg_count;
};

// ── fnc_annotation_t ─────────────────────────────────────────────────────────

struct fnc_annotation_t
{
    annotation_id_t id; ///< Set by BinaryContext on insertion; never changed after.
    std::string name;
    const abi::CallingConvention *cc = nullptr; ///< Required invariant: non-null before BinaryContext insertion.
    bool reads_global_memory = true;
    bool writes_global_memory = true;
    std::optional<uint32_t> frees_param_idx;
    std::unordered_map<uint32_t, ptr_param_t> ptr_params;
    std::optional<ret_ptr_t> ret_ptr;
    uint8_t ret_size_bytes = 0;
    bool volatile_call = true;
    bool no_return = false;
    bool is_variadic = false;
    std::optional<uint8_t> arg_count;
};

enum class builtin_annotation_kind_t
{
    lifted_core_all_registers,
    lifted_observer_all_registers,
};

// ── BinaryContext ─────────────────────────────────────────────────────────────

/// Per-binary annotation registry. Owns all fnc_annotation_t instances and the
/// LIEF Binary. Must outlive every component that holds a pointer into it
/// (Lifter, executors, pipeline).
///
/// Not thread-safe — consistent with the existing Lifter thread-safety contract.
class BinaryContext
{
  public:
    explicit BinaryContext(std::unique_ptr<LIEF::Binary> binary);

    // Non-copyable, non-movable — raw pointers into this object must remain stable.
    BinaryContext(const BinaryContext &) = delete;
    BinaryContext &operator=(const BinaryContext &) = delete;
    BinaryContext(BinaryContext &&) = delete;
    BinaryContext &operator=(BinaryContext &&) = delete;

    // ── Binary access ─────────────────────────────────────────────────────────

    /// Returns a reference to the owned binary. BinaryContext is the sole owner.
    const LIEF::Binary &binary() const;

    /// Best-effort direct-target name resolution for a binary address.
    /// Accepts either RVA or VA-style inputs and normalizes through imagebase
    /// aliases when needed. Returns nullopt if no symbol/import metadata is known.
    std::optional<std::string> symbol_name_at_rva(uint64_t rva) const;

    /// Resolve an imported-function name for a GOT/IAT slot address.
    /// Accepts either RVA or VA-style inputs and normalizes through imagebase
    /// aliases when needed. Returns nullopt if the slot is not tied to an import.
    std::optional<std::string> import_name_for_slot(uint64_t slot_rva) const;

    /// Import function annotations from a JSON object with `annotations` and/or
    /// `bindings` arrays. Rejects ambiguous names, RVAs, and site RVAs.
    llvm::Error import_annotations_from_json(std::filesystem::path path);

    // ── Lookups — const; no mutation after insertion ──────────────────────────

    const fnc_annotation_t *get_by_id(annotation_id_t id) const;

    /// Exact-name lookup first, then ELF version-stripped alias lookup
    /// (e.g. `printf@GLIBC_2.2.5` → `printf`, `foo@@VER` → `foo`).
    annotation_id_t get_by_name(const std::string &name) const;

    annotation_id_t get_ext_call(uint64_t dest_rva) const;
    annotation_id_t get_site_call(uint64_t site_rva) const;

    // ── Resolution helpers ────────────────────────────────────────────────────

    /// Precedence: site binding → callee binding → canonical-name lookup →
    /// pessimistic auto-created fallback bound at `dest_rva`.
    annotation_id_t resolve_direct_call_annotation(uint64_t                        caller_site_rva,
                                                   uint64_t                        dest_rva,
                                                   std::optional<std::string_view> resolved_name,
                                                   const abi::CallingConvention    &fallback_cc);

    /// Precedence: site binding → canonical-name lookup → pessimistic
    /// auto-created fallback bound at `caller_site_rva`.
    annotation_id_t resolve_indirect_call_annotation(uint64_t                        caller_site_rva,
                                                     std::optional<std::string_view> import_name,
                                                     const abi::CallingConvention    &fallback_cc);

    // ── Creation ──────────────────────────────────────────────────────────────

    /// Register or retrieve a binary-agnostic built-in annotation for internal lifted IR.
    annotation_id_t get_or_create_builtin_annotation(builtin_annotation_kind_t kind);

    /// Register an annotation for a known-address external call target.
    /// The annotation must carry a non-null calling convention.
    annotation_id_t create_ext_call(uint64_t dest_rva,
                                    std::unique_ptr<fnc_annotation_t> ann);

    /// Register an annotation for a call site. Used for indirect-call dispatchers
    /// and direct-call site-specific specializations.
    /// The annotation must carry a non-null calling convention.
    annotation_id_t create_site_call(uint64_t site_rva,
                                     std::unique_ptr<fnc_annotation_t> ann);

    /// Insert an annotation with no RVA binding. The annotation must carry a non-null CC.
    annotation_id_t add_annotation(std::unique_ptr<fnc_annotation_t> ann);

  private:

    /// Assigns id, inserts into annotations_, and optionally updates the public
    /// name index. Called by all public creation helpers and JSON import.
    annotation_id_t insert(std::unique_ptr<fnc_annotation_t> ann,
                           bool                              index_name = true);

    void bind_name_alias(const fnc_annotation_t &ann, std::string_view name);
    void bind_ext_call_alias(const fnc_annotation_t &ann, uint64_t dest_rva);
    void bind_site_alias(const fnc_annotation_t &ann, uint64_t site_rva);

    std::vector<uint64_t> address_aliases(uint64_t addr) const;
    static std::optional<std::string> strip_elf_symbol_version(std::string_view name);

    void index_binary_metadata();
    void index_direct_target_name(uint64_t addr, std::string_view name, bool overwrite = false);
    void index_import_slot_name(uint64_t addr, std::string_view name, bool overwrite = false);

    std::unique_ptr<LIEF::Binary> binary_;
    uint64_t next_id_raw_ = 0;

    std::unordered_map<annotation_id_t, std::unique_ptr<fnc_annotation_t>> annotations_;
    std::unordered_map<std::string, const fnc_annotation_t *> annotations_by_name_;
    std::unordered_map<uint64_t, const fnc_annotation_t *> ext_call_annotations_;
    std::unordered_map<uint64_t, const fnc_annotation_t *> site_annotations_;
    std::map<builtin_annotation_kind_t, annotation_id_t> builtin_annotation_ids_;

    std::unordered_map<uint64_t, std::string> direct_target_names_;
    std::unordered_map<uint64_t, std::string> import_slot_names_;
};

} // namespace lifted
