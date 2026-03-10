#include "lifter.hpp"

#include <remill/BC/Util.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <glog/logging.h>

#include <map>
#include <vector>

#include "../utils.hpp"

namespace lifted::lifter
{

    // ── stitch_cfg ──────────────────────────────────────────────────────────────
    //
    // Stitches a set of lifted BB functions into a single dispatcher wrapper.
    // Signature:  ptr (ptr %state, i64 %rva, ptr %memory, i64 %base)
    //
    // Each BB is dispatched by a switch on the incoming RVA.  The next BB is
    // selected each iteration by reading __extract_rip from the processor state.
    //
    // Parameters:
    //   module              - module containing clones of all BB functions
    //   blocks              - set of bb_id_t values to stitch into the CFG
    //   name                - name for the resulting wrapper function
    //   target_id           - if non-zero, intercept execution at this block
    //                         so the caller can read the resulting PC
    //   dead_end_unreachable - true for backward-slice CFGs (paths leaving the
    //                         sub-graph are unreachable); false for full CFGs
    //                         (exits return current memory)
    //   ctx                 - per-call state providing edges and synthetic block info
    //   instrument          - if true, call __lifted_bb_entered at the start of
    //                         each REAL block

    llvm::Expected<llvm::Function *> Lifter::stitch_cfg(llvm::Module *module,
                                                        const std::set<bb_id_t> &blocks,
                                                        llvm::StringRef name,
                                                        bb_id_t target_id,
                                                        bool dead_end_unreachable,
                                                        lift_context_t &ctx,
                                                        bool instrument)
    {
        if (blocks.empty())
            return static_cast<llvm::Function *>(nullptr);

        llvm::LLVMContext &Ctx = module->getContext();

        // Grab types from the first block.
        auto *template_func = module->getFunction(explored_.at(*blocks.begin()).func_name);
        if (!template_func)
            return llvm::make_error<llvm::StringError>(
                "stitch_cfg: BB function not found in module for id " +
                    llvm::utohexstr(*blocks.begin()),
                llvm::inconvertibleErrorCode());
        auto *lifted_fty = template_func->getFunctionType();
        auto *state_ptr_ty = lifted_fty->getParamType(0);
        auto *pc_ty = lifted_fty->getParamType(1);
        auto *mem_ptr_ty = lifted_fty->getParamType(2);

        // Wrapper: ptr (ptr %state, i64 %rva, ptr %memory, i64 %base)
        auto *wrapper_ty = llvm::FunctionType::get(
            mem_ptr_ty, {state_ptr_ty, pc_ty, mem_ptr_ty, pc_ty}, false);
        auto *wrapper = llvm::Function::Create(
            wrapper_ty, llvm::Function::ExternalLinkage, name, module);
        wrapper->addFnAttr(llvm::Attribute::AlwaysInline);
        wrapper->addParamAttr(0, llvm::Attribute::NoAlias);
        wrapper->addParamAttr(0, llvm::Attribute::NoCapture);
        wrapper->addParamAttr(2, llvm::Attribute::NoAlias);
        wrapper->addParamAttr(2, llvm::Attribute::NoCapture);

        auto *arg_state = wrapper->getArg(0);
        arg_state->setName("state");
        auto *arg_rva = wrapper->getArg(1);
        arg_rva->setName("rva");
        auto *arg_mem = wrapper->getArg(2);
        arg_mem->setName("memory");
        auto *arg_base = wrapper->getArg(3);
        arg_base->setName("base");

        // Helpers.
        auto *extract_rip = module->getFunction("__extract_rip");
        auto *store_rip = module->getFunction("__store_rip");
        if (!extract_rip || !store_rip)
            return llvm::make_error<llvm::StringError>(
                "stitch_cfg: __extract_rip or __store_rip not found in module",
                llvm::inconvertibleErrorCode());

        // Optional instrumentation function.
        llvm::Function *bb_entered_func = nullptr;
        if (instrument)
        {
            bb_entered_func = module->getFunction("__lifted_bb_entered");
            if (!bb_entered_func)
            {
                return llvm::make_error<llvm::StringError>(
                    "stitch_cfg: instrumentation enabled but __lifted_bb_entered not found in module",
                    llvm::inconvertibleErrorCode());
            }
        }

        // Create per-BB basic blocks.
        auto *entry_bb = llvm::BasicBlock::Create(Ctx, "entry", wrapper);
        auto *dead_end = llvm::BasicBlock::Create(Ctx, "dead_end", wrapper);
        std::map<bb_id_t, llvm::BasicBlock *> block_map;
        for (bb_id_t id : blocks)
            block_map[id] = llvm::BasicBlock::Create(
                Ctx, "bb_" + llvm::utohexstr(id), wrapper);

        // Entry block: allocate mem/pc variables, dispatch on input RVA.
        llvm::IRBuilder<> B(entry_bb);
        auto *mem_var = B.CreateAlloca(mem_ptr_ty, nullptr, "mem_var");
        auto *pc_var = B.CreateAlloca(pc_ty, nullptr, "pc_var");
        B.CreateStore(arg_mem, mem_var);
        llvm::Value *entry_pc = B.CreateAdd(arg_rva, arg_base, "entry_pc");
        B.CreateStore(entry_pc, pc_var);

        auto *entry_switch = B.CreateSwitch(arg_rva, dead_end, blocks.size());
        for (bb_id_t id : blocks)
            entry_switch->addCase(B.getInt64(id), block_map.at(id));

        // Dead-end block: unreachable in backward-slice CFGs, natural return in
        // forward CFGs.  return_bb is always a natural return — used as the
        // switch default for RETURN_TO_CALLER blocks regardless of slice mode.
        auto *return_bb = llvm::BasicBlock::Create(Ctx, "return_bb", wrapper);
        B.SetInsertPoint(dead_end);
        if (dead_end_unreachable)
            B.CreateUnreachable();
        else
            B.CreateRet(B.CreateLoad(mem_ptr_ty, mem_var));
        B.SetInsertPoint(return_bb);
        B.CreateRet(B.CreateLoad(mem_ptr_ty, mem_var));

        auto add_successor_switch_case = [&](llvm::SwitchInst *sw, bb_id_t succ, llvm::BasicBlock *dest_bb) {
            auto sit = ctx.synthetic_blocks.find(succ);
            if (sit == ctx.synthetic_blocks.end())
            {
                sw->addCase(B.getInt64(succ), dest_bb);
                return;
            }

            switch (sit->second.type)
            {
            case synthetic_block_info_t::Type::EXTERNAL:
            case synthetic_block_info_t::Type::RECURSIVE:
                sw->addCase(B.getInt64(sit->second.dest_addr.value()), dest_bb);
                break;
            case synthetic_block_info_t::Type::INDIRECT:
                break;
            }
        };


        // Stitching loop: fill each BB's basic block.
        for (bb_id_t id : blocks)
        {
            auto *current_bb = block_map.at(id);
            B.SetInsertPoint(current_bb);

            // Update block PC for REAL blocks.
            if (!is_synthetic(id))
            {
                llvm::Value *block_rva = B.getInt64(id);
                llvm::Value *block_pc = B.CreateAdd(block_rva, arg_base, "block_pc");
                B.CreateStore(block_pc, pc_var);
                B.CreateCall(store_rip, {arg_state, block_pc});
            }

            auto *source_func = module->getFunction(explored_.at(id).func_name);
            auto *curr_mem = B.CreateLoad(mem_ptr_ty, mem_var);
            auto *curr_pc = B.CreateLoad(pc_ty, pc_var);

            if (instrument && bb_entered_func && !is_synthetic(id))
                B.CreateCall(bb_entered_func, {arg_state, B.getInt64(id), curr_mem});

            auto *call = B.CreateCall(source_func, {arg_state, curr_pc, curr_mem});
            call->addFnAttr(llvm::Attribute::AlwaysInline);
            B.CreateStore(call, mem_var);

            // ── Target interception for backward-slice CFG ──────────────
            if (target_id != 0 && id == target_id)
            {
                // Extract the next RIP so loop-back edges can be dispatched.
                auto *next_rip = B.CreateCall(extract_rip, {arg_state});
                B.CreateStore(next_rip, pc_var);
                auto *next_rva = B.CreateSub(next_rip, arg_base, "next_rva");

                // Collect in-slice successors.
                std::vector<bb_id_t> in_slice;
                for (const auto &e : ctx.edges)
                    if (e.source == id && blocks.count(e.dest))
                        in_slice.push_back(e.dest);

                if (in_slice.empty())
                {
                    B.CreateRet(call);
                    continue;
                }

                // Build a ret BB as the default exit path.
                auto *ret_bb = llvm::BasicBlock::Create(Ctx, "target_exit", wrapper);
                llvm::IRBuilder<> ret_b(ret_bb);
                ret_b.CreateRet(ret_b.CreateLoad(mem_ptr_ty, mem_var));

                // Find any INDIRECT synthetic in in_slice (use as default).
                std::optional<bb_id_t> indirect_default;
                for (bb_id_t succ : in_slice)
                {
                    auto sit = ctx.synthetic_blocks.find(succ);
                    if (sit != ctx.synthetic_blocks.end() &&
                        sit->second.type == synthetic_block_info_t::Type::INDIRECT)
                    {
                        indirect_default = succ;
                        break;
                    }
                }

                auto *default_bb = indirect_default.has_value()
                                       ? block_map.at(*indirect_default)
                                       : ret_bb;
                auto *sw = B.CreateSwitch(next_rva, default_bb, in_slice.size());

                for (bb_id_t succ : in_slice)
                {
                    if (indirect_default.has_value() && succ == *indirect_default)
                        continue; // already the default

                    add_successor_switch_case(sw, succ, block_map.at(succ));
                }
                continue;
            }

            // ── Normal block: dispatch to successors ────────────────────
            auto *next_rip = B.CreateCall(extract_rip, {arg_state});
            B.CreateStore(next_rip, pc_var);
            auto *next_rva = B.CreateSub(next_rip, arg_base, "next_rva");

            // Collect successors of this block.
            std::vector<bb_id_t> successors;
            for (const auto &e : ctx.edges)
                if (e.source == id)
                    successors.push_back(e.dest);

            if (successors.empty())
            {
                // A RETURN_TO_CALLER block with no known continuation sites yet
                // still exits normally.  All other empty-successor blocks go via
                // dead_end (preserving unreachable semantics for backward slices).
                if (ctx.return_to_caller_blocks.count(id))
                    B.CreateRet(B.CreateLoad(mem_ptr_ty, mem_var));
                else
                    B.CreateBr(dead_end);
                continue;
            }

            // Identify the INDIRECT synthetic successor (used as default case).
            std::optional<bb_id_t> indirect_default;
            for (bb_id_t succ : successors)
            {
                auto sit = ctx.synthetic_blocks.find(succ);
                if (sit != ctx.synthetic_blocks.end() &&
                    sit->second.type == synthetic_block_info_t::Type::INDIRECT)
                {
                    indirect_default = succ;
                    break;
                }
            }

            // RETURN_TO_CALLER blocks use return_bb as the default so that
            // a ret to an unmapped address produces a natural NATURAL_EXIT.
            auto *natural_default = ctx.return_to_caller_blocks.count(id)
                                        ? return_bb
                                        : dead_end;
            auto *default_bb = indirect_default.has_value()
                                   ? block_map.at(*indirect_default)
                                   : natural_default;
            auto *sw = B.CreateSwitch(next_rva, default_bb, successors.size());

            for (bb_id_t succ : successors)
            {
                if (indirect_default.has_value() && succ == *indirect_default)
                    continue;

                if (!blocks.count(succ))
                {
                    sw->addCase(B.getInt64(succ), dead_end);
                    continue;
                }

                add_successor_switch_case(sw, succ, block_map.at(succ));
            }
        }

        return wrapper;
    }

    // ── concretize_cfg_base ─────────────────────────────────────────────────────
    //
    // Creates a 3-parameter wrapper around a 4-parameter (based) CFG function
    // by supplying a concrete value for the `base` parameter.

    llvm::Expected<llvm::Function *> Lifter::concretize_cfg_base(llvm::Function *based_func,
                                                                 uint64_t concrete_base,
                                                                 llvm::StringRef concrete_name)
    {
        auto *M = based_func->getParent();
        auto *based_ty = based_func->getFunctionType();
        if (based_ty->getNumParams() != 4)
            return llvm::make_error<llvm::StringError>(
                "concretize_cfg_base: expected 4-parameter based function, got " +
                    std::to_string(based_ty->getNumParams()),
                llvm::inconvertibleErrorCode());

        auto *state_ptr_ty = based_ty->getParamType(0);
        auto *rva_ty = based_ty->getParamType(1);
        auto *mem_ptr_ty = based_ty->getParamType(2);

        std::string wrapper_name = concrete_name.empty()
                                       ? (based_func->getName().str() + "_concrete")
                                       : concrete_name.str();

        auto *wrapper_ty = llvm::FunctionType::get(
            mem_ptr_ty, {state_ptr_ty, rva_ty, mem_ptr_ty}, false);
        auto *wrapper = llvm::Function::Create(
            wrapper_ty, llvm::Function::ExternalLinkage, wrapper_name, M);

        wrapper->addParamAttr(0, llvm::Attribute::NoAlias);
        wrapper->addParamAttr(0, llvm::Attribute::NoCapture);
        wrapper->addParamAttr(2, llvm::Attribute::NoAlias);
        wrapper->addParamAttr(2, llvm::Attribute::NoCapture);

        auto *arg_state = wrapper->getArg(0);
        arg_state->setName("state");
        auto *arg_rva = wrapper->getArg(1);
        arg_rva->setName("rva");
        auto *arg_mem = wrapper->getArg(2);
        arg_mem->setName("memory");

        auto *entry = llvm::BasicBlock::Create(M->getContext(), "entry", wrapper);
        llvm::IRBuilder<> B(entry);
        auto *base_val = B.getInt64(concrete_base);
        B.CreateRet(B.CreateCall(based_func, {arg_state, arg_rva, arg_mem, base_val}));

        return wrapper;
    }

    // ── build_backward_slice_cfg ────────────────────────────────────────────────

    llvm::Expected<llvm::Function *> Lifter::build_backward_slice_cfg(llvm::Module *module,
                                                                      bb_id_t target_id,
                                                                      llvm::StringRef name,
                                                                      lift_context_t &ctx,
                                                                      bool instrument)
    {
        // Compute all blocks that can REACH target_id (backward reachability).
        std::set<bb_id_t> reaching_set;
        std::vector<bb_id_t> worklist;

        reaching_set.insert(target_id);
        worklist.push_back(target_id);

        std::map<bb_id_t, std::vector<bb_id_t>> predecessors;
        for (const auto &e : ctx.edges)
            predecessors[e.dest].push_back(e.source);

        for (size_t head = 0; head < worklist.size(); ++head)
        {
            bb_id_t curr = worklist[head];
            auto it = predecessors.find(curr);
            if (it == predecessors.end())
                continue;
            for (bb_id_t pred : it->second)
            {
                if (explored_.count(pred) && !reaching_set.count(pred))
                {
                    reaching_set.insert(pred);
                    worklist.push_back(pred);
                }
            }
        }

        // Intercept at target_id; dead-ends are unreachable (backward slice only).
        return stitch_cfg(module, reaching_set, name, target_id,
                          /*dead_end_unreachable=*/true, ctx, instrument);
    }

    // ── build_forward_cfg ───────────────────────────────────────────────────────

    llvm::Expected<llvm::Function *> Lifter::build_forward_cfg(llvm::Module *module,
                                                               bb_id_t root_id,
                                                               llvm::StringRef name,
                                                               lift_context_t &ctx,
                                                               bool instrument,
                                                               std::set<edge_t> *out_edges,
                                                               std::set<lifted_bb_t> *out_blocks)
    {
        // Compute all blocks REACHABLE FROM root_id.
        std::set<bb_id_t> reachable;
        std::vector<bb_id_t> worklist;

        reachable.insert(root_id);
        worklist.push_back(root_id);

        std::map<bb_id_t, std::vector<bb_id_t>> successors;
        for (const auto &e : ctx.edges)
            successors[e.source].push_back(e.dest);

        for (size_t head = 0; head < worklist.size(); ++head)
        {
            bb_id_t curr = worklist[head];
            auto it = successors.find(curr);
            if (it == successors.end())
                continue;
            for (bb_id_t succ : it->second)
            {
                if (explored_.count(succ) && !reachable.count(succ))
                {
                    reachable.insert(succ);
                    worklist.push_back(succ);
                }
            }
        }

        // Recursive-call continuations are represented explicitly through
        // synthetic blocks, so the BFS above already captures return reachability.
        // Populate optional output sets.
        if (out_blocks)
        {
            out_blocks->clear();
            for (bb_id_t id : reachable)
            {
                auto it = explored_.find(id);
                if (it != explored_.end())
                    out_blocks->insert(it->second);
            }
        }
        if (out_edges)
        {
            out_edges->clear();
            for (const auto &e : ctx.edges)
                if (reachable.count(e.source) && reachable.count(e.dest))
                    out_edges->insert(e);
        }

        // No intercept target; exits return current memory.
        return stitch_cfg(module, reachable, name, /*target_id=*/0,
                          /*dead_end_unreachable=*/false, ctx, instrument);
    }

} // namespace lifted::lifter
