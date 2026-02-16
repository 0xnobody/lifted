
#include "lifter2.hpp"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Optimizer.h>

#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/Utils/Cloning.h>

#ifdef DEBUG
#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG
#else
#include <LIEF/LIEF.hpp>
#endif

#include <sstream>

#include "passes/analysis/stack_aa_pass.hpp"
#include "passes/deobfuscation/constant_memory_folding_pass.hpp"

#include "opt.hpp"
#include "helpers.hpp"
#include "slicer.hpp"
#include "tester.hpp"

// Specific transformation passes
#include <llvm/Transforms/Utils/Mem2Reg.h>                     // PromotePass
#include <llvm/Transforms/InstCombine/InstCombine.h>           // InstCombinePass
#include <llvm/Transforms/Scalar/DCE.h>                        // DCEPass
#include <llvm/Transforms/Scalar/SCCP.h>                       // SCCPPass
#include <llvm/Transforms/Scalar/CorrelatedValuePropagation.h> // CorrelatedValuePropagationPass
#include <llvm/Transforms/Scalar/GVN.h>                        // GVNPass
#include <llvm/Transforms/Scalar/Reassociate.h>                // ReassociatePass
#include <llvm/Transforms/Scalar/SimplifyCFG.h>                // SimplifyCFGPass
#include <llvm/Transforms/Scalar/ADCE.h>                       // AggressiveDCEPass

// #include <lifted/shared.hpp>

#include "passes/pass_utils.hpp"

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

    llvm::Function *Lifter::ConcretizeEntryPC(llvm::Function *F, unsigned pc_param_idx, bb_id_t bb_id)
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
                args.push_back(llvm::ConstantInt::get(PCParamTy, bb_id));
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

    ResolvedTargetsResult Lifter::HeuresticallyResolveIndirectTargets(llvm::Function &F)
    {
        // Match for:
        //   %r = load i64, ptr getelementptr inbounds ([0 x i8], ptr @RAM, i64 0, i64 {offs})
        //   ret i64 %r
        // Extract the offset, if within GotTableRvaRanges, we know it's an indirect jump via GOT.

        if (auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>((--F.end())->getTerminator()))
        {
            if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(ret_inst->getReturnValue()))
            {
                if (auto GEPOp = passes::isRAMGEP(load_inst->getPointerOperand()))
                {
                    auto offset = GEPOp->getOperand(2);
                    if (auto const_offset = llvm::dyn_cast<llvm::ConstantInt>(offset))
                    {
                        for (const auto &got_range : GotTableRvaRanges)
                        {
                            if (got_range.contains(const_offset->getZExtValue()))
                            {
                                DLOG(INFO) << "Heuristically resolved indirect target via GOT at offset " << std::hex << const_offset->getZExtValue() << std::dec;
                                return ResolvedTargetsResult{
                                    .Targets = {},
                                    .IndirectTarget = Callee{} // We can fill in more callee info here if needed
                                };
                            }
                        }
                    }
                }
            }
        }

        return ResolvedTargetsResult{.Targets = {}, .IndirectTarget = std::nullopt};
    }

    ResolvedTargetsResult Lifter::HeuresticallyResolveTargets(llvm::Function &F)
    {
        // TODO: use heurestics to find external targets too

        // Match for single target (i.e. opaque predicate):
        //
        // ret i64 {const}

        std::vector<ResolvedTarget> targets;

        if (auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>((--F.end())->getTerminator()))
        {
            if (auto const_ret = llvm::dyn_cast<llvm::ConstantInt>(ret_inst->getReturnValue()))
            {
                targets.push_back(ResolvedTarget{ResolvedTarget::Type::INTERNAL, static_cast<bb_id_t>(const_ret->getZExtValue()), std::nullopt});
                return ResolvedTargetsResult{targets, std::nullopt};
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
                        targets.push_back(ResolvedTarget{ResolvedTarget::Type::INTERNAL, static_cast<bb_id_t>(const_true->getZExtValue()), std::nullopt});
                        targets.push_back(ResolvedTarget{ResolvedTarget::Type::INTERNAL, static_cast<bb_id_t>(const_false->getZExtValue()), std::nullopt});
                        return ResolvedTargetsResult{targets, std::nullopt};
                    }
                }
            }
        }

        return ResolvedTargetsResult{targets, std::nullopt};
    }

    llvm::Function *Lifter::stitchCFG(
        llvm::Module *Module,
        const std::set<bb_id_t> &BlockSet,
        llvm::StringRef NewFuncName,
        bb_id_t TargetID,
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

        // TODO: Should we do this here? Or in BB_Func creation?

        // Add noalias to %state (parameter 0) and %memory (parameter 2)
        WrapperFunc->addParamAttr(0, llvm::Attribute::NoAlias); // %state
        WrapperFunc->addParamAttr(2, llvm::Attribute::NoAlias); // %memory

        // Optional: also add nocapture for better optimization
        WrapperFunc->addParamAttr(0, llvm::Attribute::NoCapture); // %state
        WrapperFunc->addParamAttr(2, llvm::Attribute::NoCapture); // %memory

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
        for (bb_id_t id : BlockSet)
        {
            BlockMap[id] = llvm::BasicBlock::Create(Ctx, "bb_" + llvm::utohexstr(id), WrapperFunc);
        }

        llvm::IRBuilder<> Builder(EntryBB);
        llvm::AllocaInst *MemVar = Builder.CreateAlloca(MemPtrTy, nullptr, "mem_var");
        llvm::AllocaInst *PCVar = Builder.CreateAlloca(PCTy, nullptr, "pc_var");

        Builder.CreateStore(ArgMem, MemVar);
        Builder.CreateStore(ArgPC, PCVar);

        // --- ENTRY DISPATCH ---
        llvm::SwitchInst *EntrySwitch = Builder.CreateSwitch(ArgPC, DeadEndBB, BlockSet.size());
        for (bb_id_t id : BlockSet)
        {
            EntrySwitch->addCase(Builder.getInt64(id), BlockMap[id]);
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
        for (bb_id_t id : BlockSet)
        {
            llvm::BasicBlock *CurrentBB = BlockMap[id];
            Builder.SetInsertPoint(CurrentBB);

            llvm::Function *SourceFunc = Module->getFunction(Explored.at(id).FuncName);

            llvm::Value *CurrMem = Builder.CreateLoad(MemPtrTy, MemVar);
            llvm::Value *CurrPC = Builder.CreateLoad(PCTy, PCVar);

            // Call & Inline
            llvm::CallInst *Call = Builder.CreateCall(SourceFunc, {ArgState, CurrPC, CurrMem});
            Call->addFnAttr(llvm::Attribute::AlwaysInline);
            Builder.CreateStore(Call, MemVar);

            // 1. Target Interception (Used by BuildPartialCFG)
            if (TargetID != 0 && id == TargetID)
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
                if (edge.first == id)
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
                // Classify successors by type and identify INDIRECT default
                std::optional<bb_id_t> IndirectDefault;

                // First pass: identify INDIRECT synthetic block for default case
                for (bb_id_t succAddr : Successors)
                {
                    auto synth_it = SyntheticBlocks.find(succAddr);
                    if (synth_it != SyntheticBlocks.end() &&
                        synth_it->second.Type == SyntheticBlockInfo::Type::INDIRECT)
                    {
                        IndirectDefault = succAddr;
                        break; // At most one INDIRECT edge per BB
                    }
                }

                // Create switch with appropriate default
                llvm::BasicBlock *DefaultBB = IndirectDefault.has_value()
                                                  ? BlockMap[IndirectDefault.value()]
                                                  : DeadEndBB;
                llvm::SwitchInst *Switch = Builder.CreateSwitch(NextRIP, DefaultBB, Successors.size());

                // Second pass: add cases for non-default successors
                for (bb_id_t succAddr : Successors)
                {
                    // Skip if this is the INDIRECT default
                    if (IndirectDefault.has_value() && succAddr == IndirectDefault.value())
                        continue;

                    if (!BlockSet.count(succAddr))
                    {
                        // Successor not in BlockSet - goes to dead end
                        Switch->addCase(Builder.getInt64(succAddr), DeadEndBB);
                        continue;
                    }

                    auto synth_it = SyntheticBlocks.find(succAddr);
                    if (synth_it != SyntheticBlocks.end())
                    {
                        // Synthetic block
                        if (synth_it->second.Type == SyntheticBlockInfo::Type::EXTERNAL)
                        {
                            // Use concrete external address as case value
                            uint64_t externalAddr = synth_it->second.DestAddr.value();
                            Switch->addCase(Builder.getInt64(externalAddr), BlockMap[succAddr]);
                        }
                        // INDIRECT type is handled as default, skip adding as case
                    }
                    else
                    {
                        // Real block - use block ID as case value
                        Switch->addCase(Builder.getInt64(succAddr), BlockMap[succAddr]);
                    }
                }
            }
        }

        return WrapperFunc;
    }

    llvm::Function *Lifter::buildPartialCFG(llvm::Module *Module, const LiftedBB &TargetBB)
    {
        bb_id_t ID = TargetBB.ID;

        // 1. COMPUTE BACKWARD SLICE
        std::set<bb_id_t> ReachingSet;
        std::vector<bb_id_t> Worklist;

        ReachingSet.insert(ID);
        Worklist.push_back(ID);

        std::map<bb_id_t, std::vector<bb_id_t>> Predecessors;
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
                for (bb_id_t predID : Predecessors[curr])
                {
                    if (Explored.count(predID) && !ReachingSet.count(predID))
                    {
                        ReachingSet.insert(predID);
                        Worklist.push_back(predID);
                    }
                }
            }
        }

        // 2. DELEGATE TO HELPER
        // Name: partial_cfg_slice_ADDR
        // TargetAddr: ADDR (Stop when reached)
        // DeadEnd: Unreachable (Strict slicing)
        std::string FuncName = "partial_cfg_" + llvm::utohexstr(ID);
        return stitchCFG(Module, ReachingSet, FuncName, ID, true);
    }

    llvm::Function *Lifter::buildCFG(llvm::Module *Module)
    {
        // 1. GATHER ALL BLOCKS
        std::set<bb_id_t> AllBlocks;
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

    ResolvedTargetsResult Lifter::ResolveTargets(const LiftedBB &BB)
    {
        // TODO: add support for external targets and indirect targets

        auto M = llvm::CloneModule(*CleanModule);

        helpers::link_deobfuscation_intrinsics(M.get());
        helpers::link_state_utils(M.get());
        helpers::link_lifting_helpers(M.get());

        llvm::Function *F = buildPartialCFG(M.get(), BB);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::always_inline(M.get());

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        runCFGPipeline(*F);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        M->getFunction("__remill_function")->replaceAllUsesWith(F);
        F->addFnAttr(llvm::Attribute::AlwaysInline);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        llvm::Function *SliceRipFnc = M->getFunction("__slice_rip");
        llvm::Function *ConcretizedFnc = ConcretizeEntryPC(SliceRipFnc, 2, InitialEntryPoint);
        SliceRipFnc->addFnAttr(llvm::Attribute::AlwaysInline);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::always_inline(M.get());

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::default_opt(M.get(), llvm::OptimizationLevel::O2);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        auto resolved_targets = HeuresticallyResolveTargets(*ConcretizedFnc);
        if (resolved_targets)
        {
            return resolved_targets;
        }

        resolved_targets = HeuresticallyResolveIndirectTargets(*ConcretizedFnc);
        if (resolved_targets)
        {
            return resolved_targets;
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

        DLOG(WARNING) << "Warning: Failed to resolve targets for BB "
                      << std::hex << BB.ID << std::dec
                      << ". This may be due to limitations in the target resolution logic.";

        return ResolvedTargetsResult{
            .Targets = {},
            .IndirectTarget = std::nullopt};
    }

    void Lifter::runCFGPipeline(llvm::Function &F)
    {
        llvm::Module *M = F.getParent();

        // Create all necessary analysis managers
        llvm::LoopAnalysisManager LAM;
        llvm::FunctionAnalysisManager FAM;
        llvm::CGSCCAnalysisManager CGAM;
        llvm::ModuleAnalysisManager MAM;

        llvm::PassBuilder PB;

        // CRITICAL: Cross-register ALL analysis managers
        PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

        // Register all analyses
        PB.registerModuleAnalyses(MAM);
        PB.registerCGSCCAnalyses(CGAM);
        PB.registerFunctionAnalyses(FAM);
        PB.registerLoopAnalyses(LAM);

        // Initial cleanup
        llvm::FunctionPassManager FPM;
        FPM.addPass(llvm::PromotePass());
        FPM.addPass(llvm::InstCombinePass());
        FPM.run(F, FAM);

        // Iterative optimization loop
        bool Changed = true;
        int Iterations = 0;
        const int MaxIterations = 3;

        while (Changed && Iterations < MaxIterations)
        {
            llvm::FunctionPassManager IterFPM;

            IterFPM.addPass(llvm::SCCPPass());
            IterFPM.addPass(llvm::CorrelatedValuePropagationPass());
            IterFPM.addPass(ConstantMemoryFoldingPass(*Binary, ConstMemoryRvaRanges));
            IterFPM.addPass(llvm::InstCombinePass());
            IterFPM.addPass(llvm::GVNPass());

            llvm::PreservedAnalyses PA = IterFPM.run(F, FAM);
            Changed = !PA.areAllPreserved();
            Iterations++;
        }

        // Final cleanup
        llvm::FunctionPassManager CleanupFPM;
        CleanupFPM.addPass(llvm::SimplifyCFGPass());
        CleanupFPM.addPass(llvm::ADCEPass());
        CleanupFPM.addPass(llvm::InstCombinePass());
        CleanupFPM.run(F, FAM);
    }

    LiftedBB Lifter::LiftBB(uintptr_t addr, std::optional<uintptr_t> stop_at)
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
        uint64_t block_end = addr;

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

            // Check if we've hit the stop boundary
            // TODO: what if no inst has been lifted? aaa
            // TODO: we should also probably handle stopping within instructions, but that's
            // more logic in the ::Lift() function. Essentially we could create an extra basic block
            // with the 'split' instruction.

            if (stop_at && inst_addr >= *stop_at)
            {
                if (inst_addr > *stop_at)
                {
                    DLOG(WARNING) << "Warning: stop address not aligned with instruction boundary at "
                                  << std::hex << inst_addr << std::dec;
                }

                // TODO: put this in a lambda or something
                const auto pc_ref = remill::LoadProgramCounterRef(block);
                const auto next_pc_ref = remill::LoadNextProgramCounterRef(block);
                auto memory = remill::NthArgument(F, remill::kMemoryPointerArgNum);
                llvm::IRBuilder<> ir(block);
                ir.CreateStore(ir.CreateLoad(Arch->AddressType(), next_pc_ref), pc_ref);
                ir.CreateRet(memory);

                break;
            }

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

            // Ignore for now:
            // kCategoryAsyncHyperCall
            // kCategoryConditionalAsyncHyperCall
            // kCategoryConditionalDirectFunctionCall
            // kCategoryConditionalIndirectFunctionCall
            //
            case remill::Instruction::kCategoryAsyncHyperCall:
            case remill::Instruction::kCategoryConditionalAsyncHyperCall:
            case remill::Instruction::kCategoryConditionalDirectFunctionCall:
            case remill::Instruction::kCategoryConditionalIndirectFunctionCall:
            {
                DLOG(WARNING) << "Warning: Unsupported instruction category "
                              << inst.category << " at "
                              << std::hex << inst_addr << std::dec;
                [[fallthrough]];
            }

            case remill::Instruction::kCategoryInvalid:
            case remill::Instruction::kCategoryError:
                remill::AddTerminatingTailCall(block, Intrinsics->error, *Intrinsics);
                break;

            case remill::Instruction::kCategoryNormal:
            case remill::Instruction::kCategoryNoOp:
                llvm::BranchInst::Create(GetOrCreateNextBlock(), block);
                break;

                // Control transfer categories:
                // kCategoryDirectJump
                // kCategoryIndirectJump
                // kCategoryConditionalIndirectJump
                // kCategoryDirectFunctionCall
                // kCategoryIndirectFunctionCall
                // kCategoryFunctionReturn
                // kCategoryConditionalBranch

            case remill::Instruction::kCategoryConditionalBranch:
            case remill::Instruction::kCategoryDirectJump:
                // In these cases, Remill doesn't store NEXT_PC into PC, as (I think) it assumed that it will
                // still be able to do it at the start of the next instruction. But since we're lifting basic
                // blocks, we finish lifting here, so we need to manually update PC with NEXT_PC.
                //
                // Then we return memory, like with normal termination.
                //
                // TODO: Perhaps add some hints regarding that we already know the targets?
                // Maybe we can use this to optimize resolving targets (i.e. checking for opaque predicates).
                {
                    const auto pc_ref = remill::LoadProgramCounterRef(block);
                    const auto next_pc_ref = remill::LoadNextProgramCounterRef(block);
                    llvm::IRBuilder<> ir(block);
                    ir.CreateStore(ir.CreateLoad(Arch->AddressType(), next_pc_ref), pc_ref);

                    // Fallthrough to ext call handling
                    [[fallthrough]];
                }
            case remill::Instruction::kCategoryIndirectJump:
            case remill::Instruction::kCategoryConditionalIndirectJump:
            case remill::Instruction::kCategoryDirectFunctionCall:
            case remill::Instruction::kCategoryIndirectFunctionCall:
            case remill::Instruction::kCategoryFunctionReturn:
            default:
                // return memory
                auto memory = remill::LoadMemoryPointer(block, *Intrinsics);
                llvm::IRBuilder<> ir(block);
                ir.CreateRet(memory);
                break;
            }
        }

        LiftedBB BB;
        BB.Type = LiftedBB::Type::REAL;
        BB.ID = addr;
        BB.FuncName = F->getName();
        BB.RVARange = llvm::AddressRange{addr, inst.next_pc};
        BB.TerminatingCategory = inst.category;

        return BB;
    }

    llvm::FunctionType *Lifter::ResolveCalleeType(const Callee &callee) const
    {
        if (callee.OrigType)
            return callee.OrigType;

        // Fall back to the calling convention's default type.
        const auto *CC = ResolveCC(callee);
        if (CC)
            return CC->getDefaultFunctionType(Module->getContext());

        return nullptr;
    }

    llvm::Function *Lifter::GetOrCreateCalleeStub(llvm::Module *M, const Callee &callee)
    {
        // Determine stub key — per callee name (or per unnamed indirect).
        std::string Key = callee.FuncName.empty()
                              ? ("indirect_" + std::to_string(NextIndirectStubID++))
                              : callee.FuncName;

        // Return existing stub if already created for this callee.
        auto it = CalleeStubs.find(Key);
        if (it != CalleeStubs.end())
        {
            if (auto *ExistingStub = M->getFunction(it->second.StubFuncName))
            {
                return ExistingStub;
            }
        }

        const auto *CC = ResolveCC(callee);
        assert(CC && "GetOrCreateCalleeStub requires a calling convention");

        // The stub has the same signature as a lifted function:
        //   ptr @__lifted_<abi>_call_<name>(ptr %state, i64 %addr, ptr %memory)
        // This is the same as __lifted_systemv_call (State*, addr_t, Memory*) → Memory*

        // Find the template stub function (linked from lifting-helper.ll).
        std::string TemplateStubName = CC->getCallStubName().str();
        llvm::Function *TemplateStub = M->getFunction(TemplateStubName);
        assert(TemplateStub && ("Missing ABI stub template: " + TemplateStubName).c_str());

        // Create a per-callee ext call declaration:
        //   declare ptr @__lifted_ext_call_<name>(ptr, i64, ptr)
        std::string ExtCallName = "__lifted_ext_call_" + Key;
        llvm::Function *ExtCallDecl = M->getFunction(ExtCallName);
        if (!ExtCallDecl)
        {
            // Same signature as __lifted_ext_call
            llvm::Function *OrigExtCall = M->getFunction("__lifted_ext_call");
            assert(OrigExtCall && "Missing __lifted_ext_call declaration");
            ExtCallDecl = llvm::Function::Create(
                OrigExtCall->getFunctionType(),
                llvm::Function::ExternalLinkage,
                ExtCallName, M);
        }

        // Clone the template stub → __lifted_<abi>_call_<name>
        std::string StubName = TemplateStubName + "_" + Key;
        llvm::ValueToValueMapTy VMap;
        llvm::Function *Stub = llvm::CloneFunction(TemplateStub, VMap);
        Stub->setName(StubName);

        // Inside the cloned stub, replace calls to __lifted_ext_call with
        // calls to __lifted_ext_call_<name>.
        llvm::Function *OrigExtCall = M->getFunction("__lifted_ext_call");
        for (auto &BB : *Stub)
        {
            for (auto &I : BB)
            {
                if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I))
                {
                    if (CI->getCalledFunction() == OrigExtCall)
                    {
                        CI->setCalledFunction(ExtCallDecl);
                    }
                }
            }
        }

        // Record the stub.
        CalleeStubs[Key] = CalleeStubEntry{Stub->getName().str(), ExtCallDecl->getName().str(), callee};
        return Stub;
    }

    LiftedBB Lifter::CreateRemoteCallSyntheticBB(bb_id_t id, std::optional<Callee> callee_info)
    {
        std::stringstream ss;
        ss << "BB_" << std::hex << id << "_indr";

        auto F = Arch->DeclareLiftedFunction(ss.str(), Module);

        Arch->InitializeEmptyLiftedFunction(F);

        auto state_ptr = NthArgument(F, remill::kStatePointerArgNum);
        auto pc = remill::LoadProgramCounterArg(F);
        auto mem = remill::LoadMemoryPointerArg(F);

        llvm::IRBuilder<> ir(&F->getEntryBlock());

        // Resolve per-callee CC.
        const abi::CallingConvention *CalleeCC = callee_info ? ResolveCC(*callee_info) : nullptr;

        if (CalleeCC && callee_info)
        {
            // Get or create the per-callee ABI stub.
            // The stub saves non-volatile regs, calls opaque __lifted_ext_call_<name>,
            // restores non-volatile regs, and pops the return address.
            llvm::Function *Stub = GetOrCreateCalleeStub(Module, *callee_info);

            // Call the stub: ptr @stub(ptr %state, i64 %addr, ptr %memory)
            llvm::Value *Result = ir.CreateCall(Stub, {state_ptr, pc, mem});
            ir.CreateRet(Result);
        }
        else
        {
            // Fallback: opaque external call via __lifted_issue_ext_call.
            llvm::Function *extFunc = Module->getFunction("__lifted_issue_ext_call");
            auto call = ir.CreateCall(extFunc, {state_ptr, pc, mem});
            ir.CreateRet(call);
        }

        return LiftedBB{
            .Type = LiftedBB::Type::SYNTHETIC,
            .ID = id,
            .FuncName = F->getName(),
            .RVARange = std::nullopt,
            .TerminatingCategory = std::nullopt};
    }

    llvm::Expected<std::pair<std::unique_ptr<llvm::Module>, llvm::Function *>> Lifter::Lift(uint64_t addr)
    {
        InitialEntryPoint = (bb_id_t)addr;

        // Link state-utils early so __extract_* and __store_* are available
        // for typed synthetic BB construction.
        helpers::link_state_utils(Module);
        helpers::link_lifting_helpers(Module);

        Worklist.push_back((bb_id_t)addr);
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

            bb_id_t curr_id = Worklist.front();
            Worklist.pop_front();

            auto get_owning_bb = [&](uintptr_t addr) -> auto
            {
                return std::find_if(Explored.begin(), Explored.end(), [&](const auto &pair)
                                    {
                    const auto &bb = pair.second;
                    return bb.Type == LiftedBB::Type::REAL && addr >= bb.RVARange->start() && addr < bb.RVARange->end(); });
            };

            if (!IsSynthetic(curr_id))
            {
                uint64_t current_addr = (uint64_t)curr_id;

                if (auto owning_bb = get_owning_bb(current_addr); owning_bb != Explored.end())
                {
                    auto original_bb_id = owning_bb->second.ID;
                    auto original_func_name = owning_bb->second.FuncName;
                    auto original_start = owning_bb->second.RVARange->start();
                    auto original_end = owning_bb->second.RVARange->end();

                    // Only split if current_addr is NOT at the start (otherwise it's an exact match)
                    if (original_start != current_addr)
                    {
                        llvm::outs() << "    [SPLIT] Block [0x" << llvm::format_hex(original_start, 16)
                                     << ", 0x" << llvm::format_hex(original_end, 16)
                                     << ") split at 0x" << llvm::format_hex(current_addr, 16) << "\n";

                        // 1. Remove original block from Explored and both Modules
                        Explored.erase(original_bb_id);
                        if (auto *old_func = Module->getFunction(original_func_name))
                        {
                            old_func->eraseFromParent();
                        }
                        if (auto *old_func = CleanModule->getFunction(original_func_name))
                        {
                            old_func->eraseFromParent();
                        }

                        // 2. Lift BOTH halves immediately (atomically)
                        LiftedBB bb_start = LiftBB(original_start, current_addr);
                        LiftedBB bb_end = LiftBB(current_addr, std::nullopt);

                        utils::output_to_file("/home/atlas/lifted/out/split.ll", Module);

                        auto BBStartFnc = Module->getFunction(bb_start.FuncName);
                        OptimizeLiftedBB(BBStartFnc);
                        remill::MoveFunctionIntoModule(BBStartFnc, CleanModule.get());
                        Explored[bb_start.ID] = bb_start;

                        auto BBEndFnc = Module->getFunction(bb_end.FuncName);
                        OptimizeLiftedBB(BBEndFnc);
                        remill::MoveFunctionIntoModule(BBEndFnc, CleanModule.get());
                        Explored[bb_end.ID] = bb_end;

                        utils::output_to_file("/home/atlas/lifted/out/split.ll", CleanModule.get());

                        // 3. Update edges: redirect outgoing edges from original_start to current_addr
                        std::vector<std::pair<bb_id_t, bb_id_t>> edges_to_remove;
                        std::vector<std::pair<bb_id_t, bb_id_t>> edges_to_add;

                        for (const auto &edge : Edges)
                        {
                            if (edge.first == original_bb_id)
                            {
                                edges_to_remove.push_back(edge);
                                edges_to_add.push_back({bb_end.ID, edge.second});
                            }
                        }

                        for (const auto &edge : edges_to_remove)
                        {
                            Edges.erase(edge);
                        }
                        for (const auto &edge : edges_to_add)
                        {
                            Edges.insert(edge);
                        }

                        // 4. Add fallthrough edge from bb_start to bb_end
                        Edges.insert({bb_start.ID, bb_end.ID});

                        // 5. Mark bb_start for reprove (it has a new outgoing edge)
                        Reprove.insert(bb_start.ID);
                    }
                }
            }

            llvm::outs() << "[*] Analyzing BB 0x" << llvm::format_hex(curr_id, 16) << "\n";

            LiftedBB BB;
            if (!Explored.contains(curr_id))
            {
                if (IsSynthetic(curr_id))
                {
                    const auto &synth_info = SyntheticBlocks.at(curr_id);
                    BB = CreateRemoteCallSyntheticBB(curr_id, synth_info.CalleeInfo);
                }
                else
                {
                    BB = LiftBB(curr_id);
                }

                auto Func = Module->getFunction(BB.FuncName);

                OptimizeLiftedBB(Func);

                remill::MoveFunctionIntoModule(Func, CleanModule.get()); // maybe need to remove old?
                Explored.insert({curr_id, BB});
            }
            else
            {
                BB = Explored.at(curr_id);
            }

            utils::output_to_file("/home/atlas/lifted/out/lifted_module.ll", CleanModule.get());

            ResolvedTargetsResult targets_result = ResolveTargets(BB);

            llvm::outs() << "    Resolved targets:\n";
            for (auto target : targets_result.Targets)
            {
                llvm::outs() << "      " << target << "\n";
            }

            for (auto target : targets_result.Targets)
            {
                switch (target.Type)
                {
                case ResolvedTarget::Type::INTERNAL:
                {
                    // Edge within the function that we want to continue lifting at.
                    //
                    // We use the normal algorithm here, adding unknown edges, and scheduling
                    // new blocks for exploration.
                    //
                    // We also update for reprove set for all blocks reachable from newly-discovered
                    // edges.

                    // Internal, so target.Dest corresponds to a lifted BB ID.
                    //
                    bb_id_t new_target_id = (bb_id_t)target.Dest;

                    bool edgeKnown = Edges.contains({curr_id, new_target_id});

                    if (!edgeKnown)
                    {
                        // Always record any newly solved edge.
                        Edges.insert({curr_id, new_target_id});
                    }

                    if (!Explored.contains(new_target_id))
                    {
                        // New block: schedule for first-time exploration.
                        Worklist.push_back(new_target_id);
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
                            dfs(new_target_id);

                            for (auto b : reachable_set)
                            {
                                Reprove.insert(b);
                            }
                        }
                    }
                    break;
                }
                case ResolvedTarget::Type::EXTERNAL:
                {
                    // We resolved an external target, so we need to create a dispatcher BB.
                    // This BB needs to be unique to the callsite. For example:
                    //
                    // 0x1100: ins1
                    // 0x1104: ins2
                    // 0x1108: call ext_func
                    // 0x110C: ins3
                    //
                    // We need to create a BB_0x1108_ext_func dispatcher that calls ext_func,
                    // then continues to the retaddr. So the stub should issue a stub call to __lifted_ext_call,
                    // pop the retaddr into rip, and update the stack. Then we can run ResolveTargets on the
                    // dispatcher BB to continue at the INTERNAL 0x110C BB.
                    //
                    // Currently, target.Dest has the address of ext_func, but we can't use that for the BB address.
                    //
                    bb_id_t dispatcher_id = NextSyntheticID++;

                    SyntheticBlocks[dispatcher_id] = SyntheticBlockInfo{
                        .Type = SyntheticBlockInfo::Type::EXTERNAL,
                        .DestAddr = target.Dest,
                        .CalleeInfo = target.CalleeInfo};

                    Edges.insert({curr_id, dispatcher_id});

                    Worklist.push_back(dispatcher_id);
                }
                break;
                }
            }

            if (targets_result.IndirectTarget)
            {
                bb_id_t dispatcher_id = NextSyntheticID++;

                SyntheticBlocks[dispatcher_id] = SyntheticBlockInfo{
                    .Type = SyntheticBlockInfo::Type::INDIRECT,
                    .DestAddr = std::nullopt,
                    .CalleeInfo = targets_result.IndirectTarget};

                Edges.insert({curr_id, dispatcher_id});

                Worklist.push_back(dispatcher_id);
            }
        }

        // Finished. Build final CFG.
        auto M = llvm::CloneModule(*CleanModule);

        helpers::link_state_utils(M.get());

        llvm::Function *FinalFunc = buildCFG(M.get());

        return std::pair<std::unique_ptr<llvm::Module>, llvm::Function *>(std::move(M), FinalFunc);

        //
        // M IS NOW PREPARED FOR TESTING.
        //

        /*
        RunTests(M.get());

        helpers::link_deobfuscation_intrinsics(M.get());

        llvm::Function *FinalFunc = buildCFG(M.get());

        opt::always_inline(M.get());

        runCFGPipeline(*FinalFunc);

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

        // temp: Let's try to link it against unfolder.
        ConcretizedFinalFunc->setName("__lifted_function");
        ConcretizedFinalFunc->addFnAttr(llvm::Attribute::AlwaysInline);

        helpers::link_abi_helpers(M.get());

        opt::always_inline(M.get());
        opt::default_opt(M.get(), llvm::OptimizationLevel::O3);

        utils::output_to_file("/home/atlas/lifted/out/final_lifted.ll", M.get());
        */
    }

    bool Lifter::RunTests(llvm::Module *M)
    {
        /*
        helpers::link_state_utils(M);

        llvm::Function *FinalFunc = buildCFG(M);
        if (!FinalFunc)
        {
            llvm::errs() << "RunTests: buildCFG returned null\n";
            return false;
        }

        if (M->getFunction("__remill_function"))
        {
            M->getFunction("__remill_function")->eraseFromParent();
        }

        FinalFunc->setName("__remill_function");

        if (auto err = helpers::link_verification_intrinsics(M))
        {
            llvm::errs() << "RunTests: failed to link verification intrinsics: " << llvm::toString(std::move(err)) << "\n";
            return false;
        }

        // Rewrite per-callee external call declarations (__lifted_ext_call_<name>)
        // back to generic __lifted_ext_call for verifier execution.
        auto *extCallFunc = M->getFunction("__lifted_ext_call");
        if (!extCallFunc)
        {
            llvm::errs() << "RunTests: missing __lifted_ext_call declaration\n";
            return false;
        }

        for (auto &[_, entry] : CalleeStubs)
        {
            if (auto *F = M->getFunction(entry.ExtCallDeclName))
            {
                F->replaceAllUsesWith(extCallFunc);
            }
        }

        std::shared_ptr<LIEF::Binary> binary_ref(
            const_cast<LIEF::Binary *>(Binary),
            [](LIEF::Binary *) {});

        auto test_result = run_verifier_test(
            FinalFunc,
            1337,
            std::move(binary_ref),
            InitialEntryPoint);

        if (!test_result)
        {
            llvm::errs() << "RunTests: " << llvm::toString(test_result.takeError()) << "\n";
            return false;
        }
        */

        return true;
    }
}