#pragma once

#include "lifter_types.hpp"
#include "lift_context.hpp"
#include "lifter_callbacks.hpp"

#include <llvm/Support/Error.h>

#include <map>
#include <memory>
#include <optional>
#include <set>

namespace llvm
{
    class Module;
    class Function;
    class FunctionType;
} // namespace llvm

namespace remill
{
    class Arch;
    class IntrinsicTable;
} // namespace remill


namespace lifted::lifter
{

    // Forward declaration — full type in standard_lifter_callbacks.hpp
    struct StandardLifterCallbacks;

    // ── Lifter ────────────────────────────────────────────────────────────────

    /// Lifts a binary's functions to LLVM IR using Remill semantics.
    ///
    /// Ownership:
    ///   - Lifter owns its LLVM module (work_module_) created from LoadArchSemantics.
    ///   - A secondary bb_cache_module_ accumulates optimized per-BB functions
    ///     across all lift() calls so BBs are not re-lifted.
    ///   - The LLVM context must outlive this Lifter.  The arch and binary pointers
    ///     must also outlive this Lifter (non-owning).
    ///
    /// Thread safety: not thread-safe; use one Lifter per thread.
    class Lifter
    {
    public:
        /// Factory: loads Remill semantics, links helpers, returns a ready Lifter.
        /// `callbacks` must outlive the Lifter.
        static llvm::Expected<Lifter> create(const remill::Arch *arch,
                                             BinaryContext      &bin_ctx,
                                             LifterCallbacks    *callbacks);

        // Move-only.
        Lifter(Lifter &&) = default;
        Lifter &operator=(Lifter &&) = default;
        Lifter(const Lifter &) = delete;
        Lifter &operator=(const Lifter &) = delete;

        /// Lift a function starting at `entry_rva`.  Already-lifted BBs are
        /// reused from the internal cache — multiple calls on one Lifter are
        /// safe and efficient.
        llvm::Expected<lift_result_t> lift(uint64_t entry_rva,
                                           lift_config_t config = {});

        /// Read-only access to the BB cache.
        const std::map<bb_id_t, lifted_bb_t> &explored() const
        {
            return explored_;
        }
        const llvm::Module &bb_cache() const { return *bb_cache_module_; }

    private:
        // Private constructor — called only by create().
        Lifter(const remill::Arch *arch,
               BinaryContext      *bin_ctx,
               LifterCallbacks    *callbacks,
               std::unique_ptr<llvm::Module> work_module);

        // ── Immutable references ───────────────────────────────────────────
        const remill::Arch *arch_;
        const remill::IntrinsicTable *intrinsics_;
        BinaryContext *bin_ctx_; ///< Non-owning; must outlive this Lifter.
        LifterCallbacks *callbacks_; // non-owning

        // ── Owned modules ──────────────────────────────────────────────────
        std::unique_ptr<llvm::Module> work_module_;     ///< Remill semantics + scratch space.
        std::unique_ptr<llvm::Module> bb_cache_module_; ///< Persistent optimised BB cache.

        // ── Shared lifter state (persists across lift() calls) ────────────
        std::map<bb_id_t, lifted_bb_t> explored_;

        bb_id_t next_synthetic_id_ = 0xFFFF'0000'0000'0000;
        unsigned next_indirect_stub_id_ = 0;
        std::map<std::string, callee_stub_entry_t> callee_stubs_;

        // ── Binary helpers ─────────────────────────────────────────────────
        bool is_executable(uint64_t addr) const;
        bool try_read_byte(uint64_t addr, uint8_t *byte) const;
        std::string read_instruction_bytes(uint64_t addr) const;

        // ── BB lifting ─────────────────────────────────────────────────────
        lifted_bb_t lift_bb(uintptr_t addr,
                            std::optional<uintptr_t> stop_at = std::nullopt);
        lifted_bb_t create_synthetic_bb(bb_id_t id,
                                        const synthetic_block_info_t &synth_info);

        /// Find the nearest already-explored REAL block whose id is strictly
        /// greater than `curr_id`.  Returns nullopt if none exists.
        std::optional<bb_id_t> find_next_explored_real_bb(bb_id_t curr_id) const;

        // ── Callee stubs ───────────────────────────────────────────────────
        /// Get or create a per-callee ABI stub in `M`.  The stub saves
        /// non-volatile registers, calls either __lifted_ext_call_<name> or
        /// __lifted_recursive_call, restores non-volatile registers, and pops
        /// the return address.
        llvm::Expected<llvm::Function *> get_or_create_callee_stub(llvm::Module *M,
                                                                   const lifted::fnc_annotation_t *annotation,
                                                                   bool recursive);

        // ── CFG construction (implemented in cfg.cpp) ──────────────────────

        llvm::Expected<llvm::Function *> stitch_cfg(llvm::Module *module,
                                                    const std::set<bb_id_t> &blocks,
                                                    llvm::StringRef name,
                                                    bb_id_t target_id,
                                                    bool dead_end_unreachable,
                                                    lift_context_t &ctx,
                                                    bool instrument = false);

        llvm::Expected<llvm::Function *> concretize_cfg_base(llvm::Function *based_func,
                                                             uint64_t concrete_base,
                                                             llvm::StringRef concrete_name = "");

        llvm::Expected<llvm::Function *> build_backward_slice_cfg(llvm::Module *module,
                                                                  bb_id_t target_id,
                                                                  llvm::StringRef name,
                                                                  lift_context_t &ctx,
                                                                  bool instrument = false);

        llvm::Expected<llvm::Function *> build_forward_cfg(llvm::Module *module,
                                                           bb_id_t root_id,
                                                           llvm::StringRef name,
                                                           lift_context_t &ctx,
                                                           bool instrument = false,
                                                           std::set<edge_t> *out_edges = nullptr,
                                                           std::set<lifted_bb_t> *out_blocks = nullptr);
    };

} // namespace lifted::lifter
