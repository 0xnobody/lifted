#pragma once

#include "compat/lief_compat.hpp"

#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace lifted::abi
{
class CallingConvention;
} // namespace lifted::abi

namespace lifted
{

// ── annotation_id_t ──────────────────────────────────────────────────────────

/// Strongly typed annotation identifier — cannot be accidentally passed as a
/// dest/dispatcher RVA.
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

// ── fnc_annotation_t ─────────────────────────────────────────────────────────

struct fnc_annotation_t
{
    annotation_id_t id; ///< Set by BinaryContext on insertion; never changed after.
    std::string name;
    const abi::CallingConvention *cc = nullptr; ///< Required invariant: non-null before BinaryContext insertion.
    bool reads_global_memory = false;
    bool writes_global_memory = false;
    std::optional<uint32_t> frees_param_idx;
    std::unordered_map<uint32_t, ptr_param_t> ptr_params;
    std::optional<ret_ptr_t> ret_ptr;
    uint8_t ret_size_bytes = 0;
    bool volatile_call = false;
    bool no_return = false;
};

enum class builtin_annotation_kind_t
{
    lifted_core_all_registers,
    lifted_observer_all_registers,
};

// ── BinaryContext ─────────────────────────────────────────────────────────────

/// Per-binary annotation registry.  Owns all fnc_annotation_t instances and the
/// LIEF Binary.  Must outlive every component that holds a pointer into it
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

    /// Returns a reference to the owned binary.  BinaryContext is the sole owner.
    const LIEF::Binary &binary() const;

    /// LIEF-backed name resolution: symbol name at a given RVA (or VA for PIE=0).
    /// Returns nullopt if no symbol is known at that address.
    std::optional<std::string> symbol_name_at_rva(uint64_t rva) const;

    // ── Lookups — const; no mutation after insertion ──────────────────────────

    const fnc_annotation_t *get_by_id(annotation_id_t id) const;
    annotation_id_t get_by_name(const std::string &name) const;
    annotation_id_t get_ext_call(uint64_t dest_rva) const;
    annotation_id_t get_indr_call(uint64_t dispatcher_rva) const;

    // ── Creation ──────────────────────────────────────────────────────────────

    /// Register or retrieve a binary-agnostic built-in annotation for internal lifted IR.
    annotation_id_t get_or_create_builtin_annotation(builtin_annotation_kind_t kind);

    /// Register an annotation for a known-address external call target.
    /// The annotation must carry a non-null calling convention.
    annotation_id_t create_ext_call(uint64_t dest_rva,
                                    std::unique_ptr<fnc_annotation_t> ann);

    /// Register an annotation for an indirect-call dispatcher block.
    /// The annotation must carry a non-null calling convention.
    annotation_id_t create_indr_call(uint64_t dispatcher_rva,
                                     std::unique_ptr<fnc_annotation_t> ann);

    /// Insert an annotation with no RVA binding. The annotation must carry a non-null CC.
    annotation_id_t add_annotation(std::unique_ptr<fnc_annotation_t> ann);

  private:
    /// Assigns id, inserts into annotations_, updates by_name index.
    /// Called by all three public creation helpers.
    annotation_id_t insert(std::unique_ptr<fnc_annotation_t> ann);

    std::unique_ptr<LIEF::Binary> binary_;
    uint64_t next_id_raw_ = 0;

    std::unordered_map<annotation_id_t, std::unique_ptr<fnc_annotation_t>> annotations_;
    std::unordered_map<std::string, const fnc_annotation_t *> annotations_by_name_;
    std::unordered_map<uint64_t, const fnc_annotation_t *> ext_call_annotations_;
    std::unordered_map<uint64_t, const fnc_annotation_t *> indr_call_annotations_;
    std::map<builtin_annotation_kind_t, annotation_id_t> builtin_annotation_ids_;
};

} // namespace lifted
