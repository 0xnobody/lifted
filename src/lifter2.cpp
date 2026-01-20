
#include "lifter2.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Optimizer.h>

#include <llvm/Transforms/IPO/AlwaysInliner.h>

#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG

#include <sstream>

#include "passes/analysis/stack_aa_pass.hpp"
#include "passes/deobfuscation/constant_memory_folding_pass.hpp"

#include "opt.hpp"
#include "helpers.hpp"
#include "slicer.hpp"

namespace lifted
{
    bool Lifter::IsExecutableSection(const uint64_t addr) const
    {
        auto format = Binary->format();
        switch (format)
        {
        case LIEF::EXE_FORMATS::FORMAT_ELF:
        {
            auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(Binary);
            auto *section = elf->section_from_virtual_address(addr);
            if (!section)
                return false;
            return section->has(LIEF::ELF::ELF_SECTION_FLAGS::SHF_EXECINSTR);
        }
        break;
        case LIEF::EXE_FORMATS::FORMAT_PE:
        {
            uint64_t address = addr - Binary->imagebase();
            auto *pe = dynamic_cast<const LIEF::PE::Binary *>(Binary);
            auto *section = pe->section_from_rva(address);
            if (!section)
                return false;
            return section->has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
        }
        break;
        case LIEF::EXE_FORMATS::FORMAT_MACHO:
        {
            auto *macho = dynamic_cast<const LIEF::MachO::Binary *>(Binary);
            auto *section = macho->section_from_virtual_address(addr);
            if (!section)
                return false;
            return section->has(LIEF::MachO::MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS);
        }
        break;
        default:
        {
            throw std::runtime_error("Unsupported LIEF format");
        }
        break;
        }
        return false;
    }

    bool Lifter::TryReadExecutableByte(uint64_t addr, uint8_t *byte)
    {
        if (!IsExecutableSection(addr))
        {
            return false;
        }
        auto content = Binary->get_content_from_virtual_address(addr, 1);
        if (content.empty())
        {
            std::cerr << "Warning: reached end of section?" << std::endl;
            return false;
        }
        if (byte != nullptr)
        {
            *byte = content[0];
        }
        return true;
    }

    std::string Lifter::ReadInstructionBytes(uint64_t addr)
    {
        auto max_inst_bytes = Arch->MaxInstructionSize(Arch->CreateInitialContext());
        std::string inst_bytes;

        for (size_t i = 0; i < max_inst_bytes; ++i)
        {
            const auto byte_addr = (addr + i);
            if (byte_addr < addr)
            {
                break; // 32- or 64-bit address overflow.
            }
            uint8_t byte = 0;
            if (!TryReadExecutableByte(byte_addr, &byte))
            {
                DLOG(WARNING) << "Couldn't read executable byte at " << std::hex
                              << byte_addr << std::dec;
                break;
            }
            inst_bytes.push_back(static_cast<char>(byte));
        }
        return inst_bytes;
    }

    void Lifter::OptimizeLiftedBB(llvm::Function *BBFunc)
    {
        opt::always_inline(BBFunc->getParent());
    }

    llvm::Function *Lifter::ConcretizeEntryPC(llvm::Function *F, unsigned pc_param_idx, uint64_t concrete_pc)
    {
        auto M = F->getParent();
        auto OldFTy = F->getFunctionType();

        // Sanity check: parameter index must be valid
        if (pc_param_idx >= OldFTy->getNumParams())
        {
            llvm::errs() << "Error: PC parameter index " << pc_param_idx
                         << " out of bounds (function has " << OldFTy->getNumParams() << " parameters)\n";
            return nullptr;
        }

        // Sanity check: parameter must be integer type
        auto PCParamTy = OldFTy->getParamType(pc_param_idx);
        if (!PCParamTy->isIntegerTy())
        {
            llvm::errs() << "Error: PC parameter at index " << pc_param_idx
                         << " is not an integer type\n";
            return nullptr;
        }

        // Create new parameter types (drop the PC parameter)
        std::vector<llvm::Type *> NewParams;
        for (unsigned i = 0; i < OldFTy->getNumParams(); ++i)
        {
            if (i != pc_param_idx)
            {
                NewParams.push_back(OldFTy->getParamType(i));
            }
        }

        auto NewFTy = llvm::FunctionType::get(
            OldFTy->getReturnType(),
            NewParams,
            OldFTy->isVarArg());

        auto NewF = llvm::Function::Create(NewFTy,
                                           F->getLinkage(),
                                           F->getName() + ".concrete",
                                           M);

        // Copy parameter attributes from original function (skip PC parameter)
        auto OldAttrs = F->getAttributes();
        std::vector<llvm::AttributeSet> ParamAttrs;
        for (unsigned i = 0; i < OldFTy->getNumParams(); ++i)
        {
            if (i != pc_param_idx)
            {
                ParamAttrs.push_back(OldAttrs.getParamAttrs(i));
            }
        }

        NewF->setAttributes(
            llvm::AttributeList::get(
                M->getContext(),
                OldAttrs.getFnAttrs(),
                OldAttrs.getRetAttrs(),
                ParamAttrs));

        // Create wrapper body
        llvm::IRBuilder<> irb(llvm::BasicBlock::Create(M->getContext(), "", NewF));
        std::vector<llvm::Value *> args;

        // Build argument list, inserting concrete PC at the right position
        unsigned new_arg_idx = 0;
        for (unsigned i = 0; i < OldFTy->getNumParams(); ++i)
        {
            if (i == pc_param_idx)
            {
                // Insert concrete PC value
                args.push_back(llvm::ConstantInt::get(PCParamTy, concrete_pc));
            }
            else
            {
                // Pass through argument from new function
                args.push_back(NewF->getArg(new_arg_idx++));
            }
        }

        auto ret_val = irb.CreateCall(F, args);
        irb.CreateRet(ret_val);

        return NewF;
    }

    std::optional<std::set<uintptr_t>> HeuresticallyResolveTargets(llvm::Function &F)
    {
        // Match for single target (i.e. opaque predicate):
        //
        // ret i64 {const}

        std::set<uintptr_t> targets;

        if (auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>((--F.end())->getTerminator()))
        {
            if (auto const_ret = llvm::dyn_cast<llvm::ConstantInt>(ret_inst->getReturnValue()))
            {
                targets.insert(static_cast<uintptr_t>(const_ret->getZExtValue()));
                return targets;
            }
        }

        // Match for two targets (select):
        //
        // %r = select i1 %cond, i64 {const_true}, i64 {const_false}
        // ret i64 %r

        if (auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>((--F.end())->getTerminator()))
        {
            if (auto select_inst = llvm::dyn_cast<llvm::SelectInst>(ret_inst->getReturnValue()))
            {
                auto true_val = select_inst->getTrueValue();
                auto false_val = select_inst->getFalseValue();

                if (auto const_true = llvm::dyn_cast<llvm::ConstantInt>(true_val))
                {
                    if (auto const_false = llvm::dyn_cast<llvm::ConstantInt>(false_val))
                    {
                        targets.insert(static_cast<uintptr_t>(const_true->getZExtValue()));
                        targets.insert(static_cast<uintptr_t>(const_false->getZExtValue()));
                        return targets;
                    }
                }
            }
        }

        return std::nullopt;
    }

    llvm::Function *Lifter::stitchCFG(
        llvm::Module *Module,
        const std::set<uintptr_t> &BlockSet,
        llvm::StringRef NewFuncName,
        uintptr_t TargetAddr,
        bool DeadEndIsUnreachable)
    {
        llvm::LLVMContext &Ctx = Module->getContext();

        // We need at least one block to determine types
        if (BlockSet.empty())
            return nullptr;

        // Grab types from the first block in the set
        llvm::Function *TemplateFunc = Module->getFunction(Explored.at(*BlockSet.begin()).FuncName);
        llvm::FunctionType *LiftedFnTy = TemplateFunc->getFunctionType();
        llvm::Type *StatePtrTy = LiftedFnTy->getParamType(0);
        llvm::Type *PCTy = LiftedFnTy->getParamType(1);
        llvm::Type *MemPtrTy = LiftedFnTy->getParamType(2);

        // Wrapper Signature: ptr (ptr %state, i64 %pc, ptr %memory)
        llvm::FunctionType *WrapperTy = llvm::FunctionType::get(MemPtrTy, {StatePtrTy, PCTy, MemPtrTy}, false);
        llvm::Function *WrapperFunc = llvm::Function::Create(WrapperTy, llvm::Function::ExternalLinkage, NewFuncName, Module);

        // Name arguments
        llvm::Argument *ArgState = WrapperFunc->getArg(0);
        ArgState->setName("state");
        llvm::Argument *ArgPC = WrapperFunc->getArg(1);
        ArgPC->setName("start_pc");
        llvm::Argument *ArgMem = WrapperFunc->getArg(2);
        ArgMem->setName("memory");

        // Helper: __extract_rip
        llvm::Function *ExtractRipFunc = Module->getFunction("__extract_rip");
        if (!ExtractRipFunc)
            return nullptr;

        // --- BLOCKS & ALLOCAS ---
        llvm::BasicBlock *EntryBB = llvm::BasicBlock::Create(Ctx, "entry", WrapperFunc);
        llvm::BasicBlock *DeadEndBB = llvm::BasicBlock::Create(Ctx, "dead_end", WrapperFunc);

        std::map<uintptr_t, llvm::BasicBlock *> BlockMap;
        for (uintptr_t addr : BlockSet)
        {
            BlockMap[addr] = llvm::BasicBlock::Create(Ctx, "bb_" + llvm::utohexstr(addr), WrapperFunc);
        }

        llvm::IRBuilder<> Builder(EntryBB);
        llvm::AllocaInst *MemVar = Builder.CreateAlloca(MemPtrTy, nullptr, "mem_var");
        llvm::AllocaInst *PCVar = Builder.CreateAlloca(PCTy, nullptr, "pc_var");

        Builder.CreateStore(ArgMem, MemVar);
        Builder.CreateStore(ArgPC, PCVar);

        // --- ENTRY DISPATCH ---
        llvm::SwitchInst *EntrySwitch = Builder.CreateSwitch(ArgPC, DeadEndBB, BlockSet.size());
        for (uintptr_t addr : BlockSet)
        {
            EntrySwitch->addCase(Builder.getInt64(addr), BlockMap[addr]);
        }

        // --- DEAD END HANDLING ---
        Builder.SetInsertPoint(DeadEndBB);
        if (DeadEndIsUnreachable)
        {
            // For Slicing: Paths leaving the subgraph are invalid
            Builder.CreateUnreachable();
        }
        else
        {
            // For Full CFG: Paths leaving the subgraph (unknown edges/returns) return current memory
            llvm::Value *FinalMem = Builder.CreateLoad(MemPtrTy, MemVar);
            Builder.CreateRet(FinalMem);
        }

        // --- STITCHING LOOP ---
        for (uintptr_t addr : BlockSet)
        {
            llvm::BasicBlock *CurrentBB = BlockMap[addr];
            Builder.SetInsertPoint(CurrentBB);

            llvm::Function *SourceFunc = Module->getFunction(Explored.at(addr).FuncName);

            llvm::Value *CurrMem = Builder.CreateLoad(MemPtrTy, MemVar);
            llvm::Value *CurrPC = Builder.CreateLoad(PCTy, PCVar);

            // Call & Inline
            llvm::CallInst *Call = Builder.CreateCall(SourceFunc, {ArgState, CurrPC, CurrMem});
            Call->addFnAttr(llvm::Attribute::AlwaysInline);
            Builder.CreateStore(Call, MemVar);

            // 1. Target Interception (Used by BuildPartialCFG)
            if (TargetAddr != 0 && addr == TargetAddr)
            {
                Builder.CreateRet(Call);
                continue;
            }

            // 2. Calculate Next Jump
            llvm::Value *NextRIP = Builder.CreateCall(ExtractRipFunc, {ArgState});
            Builder.CreateStore(NextRIP, PCVar);

            std::vector<uintptr_t> Successors;
            for (const auto &edge : Edges)
            {
                if (edge.first == addr)
                    Successors.push_back(edge.second);
            }

            if (Successors.empty())
            {
                // No outgoing edges - this is a natural terminating block (e.g., function return)
                // Return the current memory state
                llvm::Value *FinalMem = Builder.CreateLoad(MemPtrTy, MemVar);
                Builder.CreateRet(FinalMem);
            }
            else
            {
                llvm::SwitchInst *Switch = Builder.CreateSwitch(NextRIP, DeadEndBB, Successors.size());
                for (uintptr_t succAddr : Successors)
                {
                    if (BlockSet.count(succAddr))
                    {
                        Switch->addCase(Builder.getInt64(succAddr), BlockMap[succAddr]);
                    }
                    else
                    {
                        Switch->addCase(Builder.getInt64(succAddr), DeadEndBB);
                    }
                }
            }
        }

        return WrapperFunc;
    }

    llvm::Function *Lifter::buildPartialCFG(llvm::Module *Module, const LiftedBB &TargetBB)
    {
        uintptr_t TargetAddr = TargetBB.RVARange.start();

        // 1. COMPUTE BACKWARD SLICE
        std::set<uintptr_t> ReachingSet;
        std::vector<uintptr_t> Worklist;

        ReachingSet.insert(TargetAddr);
        Worklist.push_back(TargetAddr);

        std::map<uintptr_t, std::vector<uintptr_t>> Predecessors;
        for (const auto &edge : Edges)
        {
            Predecessors[edge.second].push_back(edge.first);
        }

        size_t head = 0;
        while (head < Worklist.size())
        {
            uintptr_t curr = Worklist[head++];
            if (Predecessors.count(curr))
            {
                for (uintptr_t predAddr : Predecessors[curr])
                {
                    if (Explored.count(predAddr) && !ReachingSet.count(predAddr))
                    {
                        ReachingSet.insert(predAddr);
                        Worklist.push_back(predAddr);
                    }
                }
            }
        }

        // 2. DELEGATE TO HELPER
        // Name: partial_cfg_slice_ADDR
        // TargetAddr: ADDR (Stop when reached)
        // DeadEnd: Unreachable (Strict slicing)
        std::string FuncName = "partial_cfg_" + llvm::utohexstr(TargetAddr);
        return stitchCFG(Module, ReachingSet, FuncName, TargetAddr, true);
    }

    llvm::Function *Lifter::buildCFG(llvm::Module *Module)
    {
        // 1. GATHER ALL BLOCKS
        std::set<uintptr_t> AllBlocks;
        for (const auto &pair : Explored)
        {
            AllBlocks.insert(pair.first);
        }

        // 2. DELEGATE TO HELPER
        // Name: rebuilt_cfg
        // TargetAddr: 0 (Don't stop at any specific block, run until natural exit)
        // DeadEnd: Unreachable (But terminating blocks will return naturally)
        return stitchCFG(Module, AllBlocks, "rebuilt_cfg", 0, true);
    }

    std::set<uintptr_t> Lifter::ResolveTargets(const LiftedBB &BB)
    {
        auto M = llvm::CloneModule(*CleanModule);

        helpers::link_deobfuscation_intrinsics(M.get());
        helpers::link_symbolic_helpers(M.get());

        llvm::Function *F = buildPartialCFG(M.get(), BB);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        M->getFunction("__remill_function")->replaceAllUsesWith(F);
        F->addFnAttr(llvm::Attribute::AlwaysInline);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        llvm::Function *SliceRipFnc = M->getFunction("__slice_rip");
        llvm::Function *ConcretizedFnc = ConcretizeEntryPC(SliceRipFnc, 2, BB.RVARange.start());
        SliceRipFnc->addFnAttr(llvm::Attribute::AlwaysInline);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::always_inline(M.get());

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::default_opt(M.get(), llvm::OptimizationLevel::O2);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::run_pass<ConstantMemoryFoldingPass>(*ConcretizedFnc, *Binary, ConstMemoryRvaRanges);

        // At this point we only care about the return expression; any other instructions
        // are side effects of the function and are not relevant to target resolution.

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        if (auto resolved_targets = HeuresticallyResolveTargets(*ConcretizedFnc))
        {
            return *resolved_targets;
        }

        // If we reach here, it is because we failed to resolve any concrete targets.
        // This can be due to two main reasons:
        // 1) Our heurestics failed to detect the targets (e.g. switch tables) or the rip expression
        // is too complex to be optimized by LLVM optimizations alone.
        // 2) The code jumps/returns to an addresses that are genuinely not part of the function
        // specification (e.g. return to caller)

        // In the case of 1), this is a bug / limitation and should be addressed by e.g. implementing
        // symbolic execution to extract possible targets from the rip expression, or using better
        // optimizations like souper.

        // In the case of 2), we can simply take this as "no resolvable targets", so the function 'ends'.

        // There is no simple way of differentiating between the two cases, apart from more heurestics.
        // For now, we will just log a warning and return an empty set.

        DLOG(WARNING) << "Warning: Failed to resolve targets for BB at "
                      << std::hex << BB.RVARange.start() << std::dec
                      << ". This may be due to limitations in the target resolution logic.";

        return {};
    }

    LiftedBB Lifter::LiftBB(uint64_t addr)
    {
        auto &Context = Module->getContext();

        std::stringstream ss;
        ss << "BB_" << std::hex << addr;

        auto F = Arch->DeclareLiftedFunction(ss.str(), Module);

        Arch->InitializeEmptyLiftedFunction(F);

        std::stack<uint64_t> inst_work_list;
        std::map<uint64_t, llvm::BasicBlock *> blocks;

        inst_work_list.push(addr);

        remill::Instruction inst;

        auto GetOrCreateBlock = [&](uint64_t address) -> llvm::BasicBlock *
        {
            if (blocks.count(address) == 0)
            {
                blocks[address] = llvm::BasicBlock::Create(Context, "", F);
            }
            return blocks[address];
        };

        auto GetOrCreateNextBlock = [&]() -> llvm::BasicBlock *
        {
            inst_work_list.push(inst.next_pc);
            return GetOrCreateBlock(inst.next_pc);
        };

        auto GetOrCreateBranchNotTakenBlock = [&]() -> llvm::BasicBlock *
        {
            inst_work_list.push(inst.branch_not_taken_pc);
            return GetOrCreateBlock(inst.branch_not_taken_pc);
        };

        auto state_ptr = NthArgument(F, remill::kStatePointerArgNum);

        if (auto entry_block = &(F->front()))
        {
            auto pc = remill::LoadProgramCounterArg(F);
            auto [next_pc_ref, next_pc_ref_type] =
                Arch->DefaultLifter(*Intrinsics)
                    ->LoadRegAddress(entry_block, state_ptr, remill::kNextPCVariableName);

            // Initialize `NEXT_PC`.
            (void)new llvm::StoreInst(pc, next_pc_ref, entry_block);

            // Branch to the first basic block.
            llvm::BranchInst::Create(GetOrCreateBlock(addr), entry_block);
        }

        // Decode instructions.
        while (!inst_work_list.empty())
        {
            const auto inst_addr = inst_work_list.top();
            inst_work_list.pop();

            auto block = GetOrCreateBlock(inst_addr);

            auto inst_bytes = ReadInstructionBytes(inst_addr);

            inst.Reset();

            std::ignore = Arch->DecodeInstruction(inst_addr, inst_bytes, inst, Arch->CreateInitialContext());

            auto lift_status = inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr);
            if (remill::kLiftedInstruction != lift_status)
            {
                remill::AddTerminatingTailCall(block, Intrinsics->error, *Intrinsics);
                continue;
            }

            // Connect together the basic blocks.
            switch (inst.category)
            {
            case remill::Instruction::kCategoryInvalid:
            case remill::Instruction::kCategoryError:
                remill::AddTerminatingTailCall(block, Intrinsics->error, *Intrinsics);
                break;

            case remill::Instruction::kCategoryNormal:
            case remill::Instruction::kCategoryNoOp:
                llvm::BranchInst::Create(GetOrCreateNextBlock(), block);
                break;
            case remill::Instruction::kCategoryDirectFunctionCall:
            {
                if (inst.branch_not_taken_pc != inst.branch_taken_pc)
                {
                    std::stringstream fn_ss;
                    fn_ss << "EXT_" << std::hex << inst.branch_taken_pc;

                    auto target_trace = Arch->DeclareLiftedFunction(fn_ss.str(), Module); // TODO: cache same calls
                    remill::AddCall(block, target_trace, *Intrinsics);
                }

                const auto ret_pc_ref = remill::LoadReturnProgramCounterRef(block);
                const auto next_pc_ref = remill::LoadNextProgramCounterRef(block);
                llvm::IRBuilder<> ir(block);
                ir.CreateStore(ir.CreateLoad(Arch->AddressType(), ret_pc_ref), next_pc_ref);
                ir.CreateBr(GetOrCreateBranchNotTakenBlock());

                continue;
            }
            default:
                // return memory
                auto memory = remill::NthArgument(F, remill::kMemoryPointerArgNum);
                llvm::IRBuilder<> ir(block);
                ir.CreateRet(memory);
                break;
            }
        }

        LiftedBB BB;
        BB.FuncName = F->getName();
        BB.RVARange = llvm::AddressRange{addr, inst.next_pc};
        BB.TerminatingCategory = inst.category;

        return BB;
    }

    void Lifter::Lift(uint64_t addr)
    {
        Worklist.push_back(addr);
        while (!Worklist.empty() || !Reprove.empty())
        {
            dumpLifterState();

            if (Worklist.empty())
            {
                // When there are no new blocks to discover, re-run analysis on blocks
                // whose predecessors changed.
                for (const auto &bb : Reprove)
                {
                    Worklist.push_back(bb);
                }
                Reprove.clear();
            }

            uintptr_t current_addr = Worklist.front();
            Worklist.pop_front();

            llvm::outs() << "[*] Analyzing BB at 0x" << llvm::format_hex(current_addr, 16) << "\n";

            LiftedBB BB;
            if (!Explored.contains(current_addr))
            {
                BB = LiftBB(current_addr);

                auto Func = Module->getFunction(BB.FuncName);

                OptimizeLiftedBB(Func);

                remill::MoveFunctionIntoModule(Func, CleanModule.get()); // maybe need to remove old?
                Explored.insert({current_addr, BB});
            }
            else
            {
                BB = Explored.at(current_addr);
            }

            utils::output_to_file("/home/atlas/lifted/out/lifted_module.ll", CleanModule.get());

            std::set<uintptr_t> targets = ResolveTargets(BB);

            llvm::outs() << "    Resolved targets:\n";
            for (auto target : targets)
            {
                llvm::outs() << "      0x" << llvm::format_hex(target, 16) << "\n";
            }

            for (auto target : targets)
            {
                bool edgeKnown = Edges.contains({current_addr, target});

                if (!edgeKnown)
                {
                    // Always record any newly solved edge.
                    Edges.insert({current_addr, target});
                }

                if (!Explored.contains(target))
                {
                    // New block: schedule for first-time exploration.
                    Worklist.push_back(target);
                }
                else
                {
                    // Target is already known; if this edge is new, we may have strengthened
                    // the path constraints into Target and its descendants.
                    if (!edgeKnown)
                    {
                        // Compute all BBs currently reachable from Target in the partial CFG.
                        std::set<uintptr_t> reachable_set;
                        std::function<void(uintptr_t)> dfs = [&](uintptr_t addr)
                        {
                            for (const auto &edge : Edges)
                            {
                                if (edge.first == addr && !reachable_set.contains(edge.second))
                                {
                                    reachable_set.insert(edge.second);
                                    dfs(edge.second);
                                }
                            }
                        };
                        dfs(target);

                        for (auto b : reachable_set)
                        {
                            Reprove.insert(b);
                        }
                    }
                }
            }
        }

        // Finished. Build final CFG.
        auto M = llvm::CloneModule(*CleanModule);

        helpers::link_deobfuscation_intrinsics(M.get());
        helpers::link_symbolic_helpers(M.get());

        llvm::Function *FinalFunc = buildCFG(M.get());
        FinalFunc->addFnAttr(llvm::Attribute::AlwaysInline);

        llvm::Function *ConcretizedFinalFunc = ConcretizeEntryPC(FinalFunc, 1, addr);

        utils::output_to_file("/home/atlas/lifted/out/final_lifted.ll", M.get());

        for (auto &F : *M)
        {
            if (F.getName().starts_with("BB_"))
            {
                F.addFnAttr(llvm::Attribute::AlwaysInline);
            }
        }

        opt::always_inline(M.get());
        opt::default_opt(M.get(), llvm::OptimizationLevel::O2);

        utils::output_to_file("/home/atlas/lifted/out/final_lifted.ll", M.get());

        // Probably wasteful to run it again, since we already run it during partial CFG.
        // But easier.
        // TODO: maybe leave for caller?
        //
        opt::run_pass<ConstantMemoryFoldingPass>(*ConcretizedFinalFunc, *Binary, ConstMemoryRvaRanges);
        opt::default_opt(M.get(), llvm::OptimizationLevel::O2);

        // temp: Let's try to link it against unfolder.
        ConcretizedFinalFunc->setName("__lifted_function");
        ConcretizedFinalFunc->addFnAttr(llvm::Attribute::AlwaysInline);

        helpers::link_abi_helpers(M.get());

        opt::always_inline(M.get());
        opt::default_opt(M.get(), llvm::OptimizationLevel::O3);

        auto new_func = M->getFunction("__unfold_function_systemv_x64_abi");

        opt::run_pass<ConstantMemoryFoldingPass>(*new_func, *Binary, ConstMemoryRvaRanges);
        opt::default_opt(M.get(), llvm::OptimizationLevel::O2);
        opt::run_pass<ConstantMemoryFoldingPass>(*new_func, *Binary, ConstMemoryRvaRanges);
        opt::default_opt(M.get(), llvm::OptimizationLevel::O2);
        opt::run_pass<ConstantMemoryFoldingPass>(*new_func, *Binary, ConstMemoryRvaRanges);

        utils::output_to_file("/home/atlas/lifted/out/final_lifted.ll", M.get());
    }
}