
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
#include "utils.hpp"

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

#define LIFTER_VERBOSE

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
#ifdef LIFTER_VERBOSE
                DLOG(WARNING) << "Couldn't read executable byte at " << std::hex
                              << byte_addr << std::dec;
#endif
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
#ifdef LIFTER_VERBOSE
                                DLOG(INFO) << "Heuristically resolved indirect target via GOT at offset " << std::hex << const_offset->getZExtValue() << std::dec;
#endif
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

    static bool CollectReturnConstants(
        llvm::Value *V,
        llvm::SmallPtrSetImpl<llvm::Value *> &Visited,
        llvm::SmallSetVector<uint64_t, 4> &Out)
    {
        if (!V || !Visited.insert(V).second)
            return true;

        if (auto *C = llvm::dyn_cast<llvm::ConstantInt>(V))
        {
            Out.insert(C->getZExtValue());
            return true;
        }
        if (auto *Phi = llvm::dyn_cast<llvm::PHINode>(V))
        {
            for (llvm::Value *Inc : Phi->incoming_values())
                if (!CollectReturnConstants(Inc, Visited, Out))
                    return false;
            return true;
        }
        if (auto *Sel = llvm::dyn_cast<llvm::SelectInst>(V))
        {
            return CollectReturnConstants(Sel->getTrueValue(), Visited, Out) && CollectReturnConstants(Sel->getFalseValue(), Visited, Out);
        }
        return false; // unresolvable
    }

    ResolvedTargetsResult Lifter::HeuresticallyResolveTargets(llvm::Function &F)
    {
        auto is_external = [this](uint64_t rva)
        {
            for (const auto &ext_range : ExtFuncRvaRanges)
            {
                if (ext_range.contains(rva))
                {
                    return true;
                }
            }
            return false;
        };

        llvm::SmallSetVector<uint64_t, 4> rvas;
        llvm::SmallPtrSet<llvm::Value *, 16> visited;

        for (auto &BB : F)
        {
            auto *Ret = llvm::dyn_cast<llvm::ReturnInst>(BB.getTerminator());
            if (!Ret)
                continue;
            if (!CollectReturnConstants(Ret->getReturnValue(), visited, rvas))
                return ResolvedTargetsResult{{}, std::nullopt};
        }

        std::vector<ResolvedTarget> targets;
        for (uint64_t rva : rvas)
            targets.push_back(ResolvedTarget{
                .Type = is_external(rva) ? ResolvedTarget::Type::EXTERNAL
                                         : ResolvedTarget::Type::INTERNAL,
                .Dest = rva,
                .CalleeInfo = Callee{}});

        return ResolvedTargetsResult{targets, std::nullopt};
    }

    llvm::Function *Lifter::stitchCFG(
        llvm::Module *Module,
        const std::set<bb_id_t> &BlockSet,
        llvm::StringRef NewFuncName,
        bb_id_t TargetID,
        bool DeadEndIsUnreachable,
        bool InstrumentBasicBlockEntry)
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

        // Wrapper Signature: ptr (ptr %state, i64 %rva, ptr %memory, i64 %base)
        llvm::FunctionType *WrapperTy = llvm::FunctionType::get(MemPtrTy, {StatePtrTy, PCTy, MemPtrTy, PCTy}, false);
        llvm::Function *WrapperFunc = llvm::Function::Create(WrapperTy, llvm::Function::ExternalLinkage, NewFuncName, Module);
        WrapperFunc->addFnAttr(llvm::Attribute::AlwaysInline); // In case it has any callers later

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
        llvm::Argument *ArgRVA = WrapperFunc->getArg(1);
        ArgRVA->setName("rva");
        llvm::Argument *ArgMem = WrapperFunc->getArg(2);
        ArgMem->setName("memory");
        llvm::Argument *ArgBase = WrapperFunc->getArg(3);
        ArgBase->setName("base");

        // Helpers: __extract_rip, __store_rip
        llvm::Function *ExtractRipFunc = Module->getFunction("__extract_rip");
        llvm::Function *StoreRipFunc = Module->getFunction("__store_rip");
        if (!ExtractRipFunc || !StoreRipFunc)
            return nullptr;

        // Helper: __lifted_bb_entered (for instrumentation)
        llvm::Function *BBEnteredFunc = nullptr;
        if (InstrumentBasicBlockEntry)
        {
            BBEnteredFunc = Module->getFunction("__lifted_bb_entered");
            if (!BBEnteredFunc)
            {
                llvm::FunctionType *BBEnteredTy = llvm::FunctionType::get(StatePtrTy, {StatePtrTy, PCTy, MemPtrTy}, false);
                BBEnteredFunc = llvm::Function::Create(BBEnteredTy, llvm::Function::ExternalLinkage, "__lifted_bb_entered", Module);
                BBEnteredFunc->addFnAttr(llvm::Attribute::AlwaysInline);
            }
        }

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
        // Compute VA from RVA + base and store in pc_var
        llvm::Value *EntryPC = Builder.CreateAdd(ArgRVA, ArgBase, "entry_pc");
        Builder.CreateStore(EntryPC, PCVar);

        // --- ENTRY DISPATCH ---
        // Entry dispatch switches on RVA directly (parameter)
        llvm::SwitchInst *EntrySwitch = Builder.CreateSwitch(ArgRVA, DeadEndBB, BlockSet.size());
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

            // Set CurrPC & RIP here to the block's address (if not synthetic)
            //
            // This shouldn't really be needed (LLVM opts should be able to infer the PC from the
            // switch cases), but it might help optimization here. Although it's more of a bandaid
            // fix -- the true fix is creating a pass pipeline which propagates this information
            // backwards properly.
            //
            // This should be based (not RVA) as we are working with actual addresses not BB IDs.
            //
            if (!IsSynthetic(id))
            {
                llvm::Value *BlockRVA = Builder.getInt64(id);
                llvm::Value *BlockPC = Builder.CreateAdd(BlockRVA, ArgBase, "block_pc");
                Builder.CreateStore(BlockPC, PCVar);
                Builder.CreateCall(StoreRipFunc, {ArgState, BlockPC});
            }

            llvm::Function *SourceFunc = Module->getFunction(Explored.at(id).FuncName);

            llvm::Value *CurrMem = Builder.CreateLoad(MemPtrTy, MemVar);
            // Load VA from pc_var (it stores absolute addresses)
            llvm::Value *CurrPC = Builder.CreateLoad(PCTy, PCVar);

            // Instrument REAL basic blocks if enabled
            if (InstrumentBasicBlockEntry && BBEnteredFunc)
            {
                // Check if this is a REAL block (not synthetic)
                if (!IsSynthetic(id))
                {
                    Builder.CreateCall(BBEnteredFunc, {ArgState, Builder.getInt64(id), CurrMem});
                }
            }

            // Call & Inline
            llvm::CallInst *Call = Builder.CreateCall(SourceFunc, {ArgState, CurrPC, CurrMem});
            Call->addFnAttr(llvm::Attribute::AlwaysInline);
            Builder.CreateStore(Call, MemVar);

            // 1. Target Interception (Used by BuildPartialCFG)
            // For the terminal block we still need to dispatch back-edges that stay within
            // the slice (e.g. loop edges TargetID→predecessor→TargetID), so the optimizer
            // can observe those paths and resolve the exit target.  Only successors that are
            // in BlockSet are added as switch cases — everything else hits the default `ret`,
            // which is the exit path that ResolveTargets reads.
            if (TargetID != 0 && id == TargetID)
            {
                // Extract the next RIP so we can dispatch loop-back edges.
                llvm::Value *TargetNextRIP = Builder.CreateCall(ExtractRipFunc, {ArgState});
                Builder.CreateStore(TargetNextRIP, PCVar);
                llvm::Value *TargetNextRVA = Builder.CreateSub(TargetNextRIP, ArgBase, "next_rva");

                // Collect all successors of the target block.
                std::vector<uintptr_t> TargetSuccessors;
                for (const auto &edge : Edges)
                    if (edge.Source == id)
                        TargetSuccessors.push_back(edge.Dest);

                // Partition: in-slice (loop-back) vs. out-of-slice (exit paths).
                std::vector<uintptr_t> InSlice;
                for (bb_id_t succAddr : TargetSuccessors)
                    if (BlockSet.count(succAddr))
                        InSlice.push_back(succAddr);

                if (InSlice.empty())
                {
                    // No loop-back edges in slice — pure exit, same as before.
                    Builder.CreateRet(Call);
                }
                else
                {
                    // Create a dedicated ret BB as the default (exit) case.
                    llvm::BasicBlock *RetBB = llvm::BasicBlock::Create(
                        Module->getContext(), "target_exit", WrapperFunc);
                    llvm::IRBuilder<> RetBuilder(RetBB);
                    RetBuilder.CreateRet(RetBuilder.CreateLoad(MemPtrTy, MemVar));

                    // Identify INDIRECT synthetic among in-slice successors.
                    std::optional<bb_id_t> InSliceIndirect;
                    for (bb_id_t succAddr : InSlice)
                    {
                        auto synth_it = SyntheticBlocks.find(succAddr);
                        if (synth_it != SyntheticBlocks.end() &&
                            synth_it->second.Type == SyntheticBlockInfo::Type::INDIRECT)
                        {
                            InSliceIndirect = succAddr;
                            break;
                        }
                    }

                    // Default: use INDIRECT in-slice block if present, else the ret BB.
                    llvm::BasicBlock *DefaultBB = InSliceIndirect.has_value()
                                                      ? BlockMap[InSliceIndirect.value()]
                                                      : RetBB;
                    llvm::SwitchInst *Switch =
                        Builder.CreateSwitch(TargetNextRVA, DefaultBB, InSlice.size());

                    for (bb_id_t succAddr : InSlice)
                    {
                        if (InSliceIndirect.has_value() && succAddr == InSliceIndirect.value())
                            continue; // Already the default.

                        auto synth_it = SyntheticBlocks.find(succAddr);
                        if (synth_it != SyntheticBlocks.end())
                        {
                            if (synth_it->second.Type == SyntheticBlockInfo::Type::EXTERNAL)
                            {
                                uint64_t externalAddr = synth_it->second.DestAddr.value();
                                Switch->addCase(Builder.getInt64(externalAddr), BlockMap[succAddr]);
                            }
                            // INDIRECT: already handled as default above.
                        }
                        else
                        {
                            Switch->addCase(Builder.getInt64(succAddr), BlockMap[succAddr]);
                        }
                    }
                }
                continue;
            }

            // 2. Calculate Next Jump
            llvm::Value *NextRIP = Builder.CreateCall(ExtractRipFunc, {ArgState});
            // Store VA in pc_var for next iteration
            Builder.CreateStore(NextRIP, PCVar);
            // Convert VA to RVA for switch dispatch
            llvm::Value *NextRVA = Builder.CreateSub(NextRIP, ArgBase, "next_rva");

            std::vector<uintptr_t> Successors;
            for (const auto &edge : Edges)
            {
                if (edge.Source == id)
                    Successors.push_back(edge.Dest);
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
                llvm::SwitchInst *Switch = Builder.CreateSwitch(NextRVA, DefaultBB, Successors.size());

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

    llvm::Function *Lifter::concretizeCFGBase(llvm::Function *BasedFunc, uint64_t ConcreteBase, llvm::StringRef ConcreteName)
    {
        llvm::Module *Module = BasedFunc->getParent();
        llvm::LLVMContext &Ctx = Module->getContext();

        // Get the based function's type: ptr (ptr, i64, ptr, i64)
        llvm::FunctionType *BasedFnTy = BasedFunc->getFunctionType();
        if (BasedFnTy->getNumParams() != 4)
            return nullptr; // Not a based CFG function

        llvm::Type *StatePtrTy = BasedFnTy->getParamType(0);
        llvm::Type *RVATy = BasedFnTy->getParamType(1);
        llvm::Type *MemPtrTy = BasedFnTy->getParamType(2);

        // Create wrapper with 3-parameter signature: ptr (ptr %state, i64 %rva, ptr %memory)
        llvm::FunctionType *WrapperTy = llvm::FunctionType::get(MemPtrTy, {StatePtrTy, RVATy, MemPtrTy}, false);

        // Generate wrapper name
        std::string WrapperName;
        if (ConcreteName.empty())
        {
            WrapperName = BasedFunc->getName().str() + "_concrete";
        }
        else
        {
            WrapperName = ConcreteName.str();
        }

        llvm::Function *WrapperFunc = llvm::Function::Create(WrapperTy, llvm::Function::ExternalLinkage, WrapperName, Module);

        // Add same attributes as based function
        WrapperFunc->addParamAttr(0, llvm::Attribute::NoAlias);   // %state
        WrapperFunc->addParamAttr(2, llvm::Attribute::NoAlias);   // %memory
        WrapperFunc->addParamAttr(0, llvm::Attribute::NoCapture); // %state
        WrapperFunc->addParamAttr(2, llvm::Attribute::NoCapture); // %memory

        // Name arguments
        llvm::Argument *ArgState = WrapperFunc->getArg(0);
        ArgState->setName("state");
        llvm::Argument *ArgRVA = WrapperFunc->getArg(1);
        ArgRVA->setName("rva");
        llvm::Argument *ArgMem = WrapperFunc->getArg(2);
        ArgMem->setName("memory");

        // Build wrapper body
        llvm::BasicBlock *EntryBB = llvm::BasicBlock::Create(Ctx, "entry", WrapperFunc);
        llvm::IRBuilder<> Builder(EntryBB);

        // Create constant for concrete base
        llvm::Value *ConcreteBaseVal = Builder.getInt64(ConcreteBase);

        // Call based function with concrete base
        llvm::Value *Result = Builder.CreateCall(BasedFunc, {ArgState, ArgRVA, ArgMem, ConcreteBaseVal});

        // Return memory pointer
        Builder.CreateRet(Result);

        return WrapperFunc;
    }

    llvm::Function *Lifter::buildBackwardSliceCFG(llvm::Module *Module, bb_id_t TargetID, llvm::StringRef Name,
                                                  bool InstrumentBasicBlockEntry)
    {
        // Compute all blocks that can reach TargetID by walking predecessor edges.
        std::set<bb_id_t> ReachingSet;
        std::vector<bb_id_t> Worklist;

        ReachingSet.insert(TargetID);
        Worklist.push_back(TargetID);

        std::map<bb_id_t, std::vector<bb_id_t>> Predecessors;
        for (const auto &edge : Edges)
            Predecessors[edge.Dest].push_back(edge.Source);

        size_t head = 0;
        while (head < Worklist.size())
        {
            bb_id_t curr = Worklist[head++];
            auto it = Predecessors.find(curr);
            if (it != Predecessors.end())
            {
                for (bb_id_t predID : it->second)
                {
                    if (Explored.count(predID) && !ReachingSet.count(predID))
                    {
                        ReachingSet.insert(predID);
                        Worklist.push_back(predID);
                    }
                }
            }
        }

        // Stitch: intercept execution at TargetID (so callers can read the resulting PC).
        // Dead ends are unreachable — paths that don't reach TargetID are invalid.
        return stitchCFG(Module, ReachingSet, Name, TargetID, /*DeadEndIsUnreachable=*/true, InstrumentBasicBlockEntry);
    }

    llvm::Function *Lifter::buildForwardCFG(llvm::Module *Module, bb_id_t RootID, llvm::StringRef Name,
                                            bool InstrumentBasicBlockEntry,
                                            std::set<Edge> *OutEdges, std::set<LiftedBB> *OutBlocks)
    {
        // Compute all blocks reachable FROM RootID by following successor edges.
        std::set<bb_id_t> ReachableSet;
        std::vector<bb_id_t> Worklist;

        ReachableSet.insert(RootID);
        Worklist.push_back(RootID);

        // Build successors map for efficient lookup.
        std::map<bb_id_t, std::vector<bb_id_t>> Successors;
        for (const auto &edge : Edges)
            Successors[edge.Source].push_back(edge.Dest);

        size_t head = 0;
        while (head < Worklist.size())
        {
            bb_id_t curr = Worklist[head++];
            auto it = Successors.find(curr);
            if (it != Successors.end())
            {
                for (bb_id_t succID : it->second)
                {
                    if (Explored.count(succID) && !ReachableSet.count(succID))
                    {
                        ReachableSet.insert(succID);
                        Worklist.push_back(succID);
                    }
                }
            }
        }

        // Populate optional outputs.
        if (OutBlocks)
        {
            OutBlocks->clear();
            for (bb_id_t id : ReachableSet)
            {
                auto it = Explored.find(id);
                if (it != Explored.end())
                    OutBlocks->insert(it->second);
            }
        }
        if (OutEdges)
        {
            OutEdges->clear();
            for (const auto &edge : Edges)
            {
                if (ReachableSet.count(edge.Source) && ReachableSet.count(edge.Dest))
                    OutEdges->insert(edge);
            }
        }

        // Stitch: no intercept target, dead ends return current memory (natural function exits).
        return stitchCFG(Module, ReachableSet, Name, /*TargetID=*/0, /*DeadEndIsUnreachable=*/false, InstrumentBasicBlockEntry);
    }

    ResolvedTargetsResult Lifter::ResolveTargets(const LiftedBB &BB, uint64_t entry_rva)
    {
        auto M = llvm::CloneModule(*CleanModule);

        helpers::link_deobfuscation_intrinsics(M.get());
        helpers::link_state_utils(M.get());
        helpers::link_lifting_helpers(M.get());

        llvm::Function *F_CFG = buildBackwardSliceCFG(M.get(), BB.ID, "__lifted_partial_cfg_" + llvm::utohexstr(BB.ID));
        llvm::Function *F = concretizeCFGBase(F_CFG, 0, F_CFG->getName().str() + "_rva_based");

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        opt::always_inline(M.get());

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        runCFGPipeline(*F);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        M->getFunction("__remill_function")->replaceAllUsesWith(F);
        F->addFnAttr(llvm::Attribute::AlwaysInline);

        utils::output_to_file("/home/atlas/lifted/out/slice.ll", M.get());

        llvm::Function *SliceRipFnc = M->getFunction("__slice_rip");
        llvm::Function *ConcretizedFnc = ConcretizeEntryPC(SliceRipFnc, 2, entry_rva);
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

#ifdef LIFTER_VERBOSE
        DLOG(WARNING) << "Warning: Failed to resolve targets for BB "
                      << std::hex << BB.ID << std::dec
                      << ". This may be due to limitations in the target resolution logic.";
#endif
        return ResolvedTargetsResult{
            .Targets = {},
            .IndirectTarget = std::nullopt};
    }

    void Lifter::reproveSubtree(bb_id_t root)
    {
        // BFS over the partial CFG from `root`, inserting every reachable block
        // (including root itself) into Reprove. Called whenever a new predecessor
        // edge is added to an already-explored block.
        std::set<bb_id_t> visited;
        std::vector<bb_id_t> stack = {root};
        while (!stack.empty())
        {
            bb_id_t curr = stack.back();
            stack.pop_back();
            if (!visited.insert(curr).second)
                continue;
            Reprove.insert(curr);
            for (const auto &edge : Edges)
            {
                if (edge.Source == curr && !visited.count(edge.Dest))
                    stack.push_back(edge.Dest);
            }
        }
    }

    std::optional<bb_id_t> Lifter::findNextExploredRealBB(bb_id_t curr_id) const
    {
        // Explored is a std::map<bb_id_t, LiftedBB> ordered by start address.
        // upper_bound gives us the first entry with ID > curr_id in O(log n).
        auto it = Explored.upper_bound(curr_id);
        while (it != Explored.end())
        {
            if (it->second.Type == LiftedBB::Type::REAL)
                return it->first;
            ++it;
        }
        return std::nullopt;
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
        // DLOG(INFO) << "Lifting BB at address " << std::hex << addr << std::dec;

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
#ifdef LIFTER_VERBOSE
                    DLOG(WARNING) << "Warning: stop address not aligned with instruction boundary at "
                                  << std::hex << inst_addr << std::dec;
#endif
                }

                // TODO: put this in a lambda or something
                const auto pc_ref = remill::LoadProgramCounterRef(block);
                const auto next_pc_ref = remill::LoadNextProgramCounterRef(block);
                auto memory = remill::NthArgument(F, remill::kMemoryPointerArgNum);
                llvm::IRBuilder<> ir(block);
                ir.CreateStore(ir.CreateLoad(Arch->AddressType(), next_pc_ref), pc_ref);
                ir.CreateRet(memory);

                // The stop_at boundary actually fired — mark this before returning.
                // This distinguishes a genuine truncation from the case where the
                // block's natural terminator happens to end exactly at stop_at.
                LiftedBB TruncatedBB;
                TruncatedBB.Type = LiftedBB::Type::REAL;
                TruncatedBB.ID = addr;
                TruncatedBB.FuncName = F->getName();
                TruncatedBB.RVARange = llvm::AddressRange{addr, inst_addr};
                TruncatedBB.TerminatingCategory = std::nullopt; // no natural terminator decoded
                TruncatedBB.WasTruncatedByStop = true;
                return TruncatedBB;
            }

            auto inst_bytes = ReadInstructionBytes(inst_addr);

            inst.Reset();

            std::ignore = Arch->DecodeInstruction(inst_addr, inst_bytes, inst, Arch->CreateInitialContext());

            // DLOG(INFO) << utils::insn_bytes_to_str(std::span<const uint8_t>((const uint8_t *)inst_bytes.data(), inst_bytes.size()), inst_addr);

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
#ifdef LIFTER_VERBOSE
                DLOG(WARNING) << "Warning: Unsupported instruction category "
                              << inst.category << " at "
                              << std::hex << inst_addr << std::dec;
#endif
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

        // DLOG(INFO) << "Finished lifting BB at address " << std::hex << addr << std::dec << ":";
        // DLOG(INFO) << "\tRVA Range: [" << std::hex << addr << ", " << inst.next_pc << std::dec << ")";
        // DLOG(INFO) << "\tTerminating Category: " << inst.category;

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
        const abi::CallingConvention *CalleeCC = ResolveCC(callee_info);

        if (CalleeCC)
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

    llvm::Expected<LiftResult> Lifter::Lift(uint64_t entry_rva, bool InstrumentBasicBlockEntry)
    {
        // Link state-utils early so __extract_* and __store_* are available
        // for typed synthetic BB construction.
        helpers::link_state_utils(Module);
        helpers::link_lifting_helpers(Module);

        Worklist.push_back((bb_id_t)entry_rva);
        while (!Worklist.empty() || !Reprove.empty())
        {
#ifdef LIFTER_VERBOSE
            dumpLifterState();
#endif

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
#ifdef LIFTER_VERBOSE
                        llvm::outs() << "    [SPLIT] Block [0x" << llvm::format_hex(original_start, 16)
                                     << ", 0x" << llvm::format_hex(original_end, 16)
                                     << ") split at 0x" << llvm::format_hex(current_addr, 16) << "\n";
#endif
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
                        std::vector<Edge> edges_to_remove;
                        std::vector<Edge> edges_to_add;

                        for (const auto &edge : Edges)
                        {
                            if (edge.Source == original_bb_id)
                            {
                                edges_to_remove.push_back(edge);
                                // Preserve edge type when redirecting
                                edges_to_add.push_back(Edge{bb_end.ID, edge.Dest, edge.Type});
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
                        Edges.insert(Edge{bb_start.ID, bb_end.ID, Edge::Type::FALLTHROUGH});

                        // 5. Mark bb_start for reprove (it has a new outgoing edge)
                        Reprove.insert(bb_start.ID);
                    }
                }
            }

#ifdef LIFTER_VERBOSE
            llvm::outs() << "[*] Analyzing BB 0x" << llvm::format_hex(curr_id, 16) << "\n";
#endif

            LiftedBB BB;
            std::optional<bb_id_t> maybe_stop;
            if (!Explored.contains(curr_id))
            {
                if (IsSynthetic(curr_id))
                {
                    const auto &synth_info = SyntheticBlocks.at(curr_id);
                    BB = CreateRemoteCallSyntheticBB(curr_id, synth_info.CalleeInfo);
                }
                else
                {
                    // Clamp the lift to the nearest already-explored real block so we
                    // don't overrun a block that was discovered before us (e.g. BB1
                    // discovered before BB0 which falls through into it).
                    maybe_stop = findNextExploredRealBB(curr_id);
                    BB = LiftBB(curr_id, maybe_stop);
                }

                auto Func = Module->getFunction(BB.FuncName);

                OptimizeLiftedBB(Func);

                remill::MoveFunctionIntoModule(Func, CleanModule.get()); // maybe need to remove old?
                Explored.insert({curr_id, BB});

                // If the lift was genuinely truncated by an already-explored block,
                // record a FALLTHROUGH edge and reprove the target's subtree (new
                // predecessor may change its backward slice).  Skip ResolveTargets —
                // the only outgoing edge is the FALLTHROUGH we just recorded.
                //
                // WasTruncatedByStop is set by LiftBB when the stop_at boundary
                // actually fired, as opposed to the block ending naturally at an
                // address that coincides with stop_at (e.g. a JMP whose last byte
                // lands exactly on the start of the next known block).
                if (!IsSynthetic(curr_id) && BB.WasTruncatedByStop)
                {
#ifdef LIFTER_VERBOSE
                    llvm::outs() << "    [FALLTHROUGH] BB 0x" << llvm::format_hex(curr_id, 16)
                                 << " -> 0x" << llvm::format_hex(*maybe_stop, 16) << "\n";
#endif
                    Edges.insert(Edge{curr_id, *maybe_stop, Edge::Type::FALLTHROUGH});
                    reproveSubtree(*maybe_stop);
                    continue;
                }
            }
            else
            {
                BB = Explored.at(curr_id);
            }

            utils::output_to_file("/home/atlas/lifted/out/lifted_module.ll", CleanModule.get());

            ResolvedTargetsResult targets_result = ResolveTargets(BB, entry_rva);

#ifdef LIFTER_VERBOSE
            llvm::outs() << "Resolved targets for 0x" << llvm::format_hex(BB.ID, 16) << ":\n";
            for (auto target : targets_result.Targets)
            {
                llvm::outs() << "\t" << target << "\n";
            }
#endif
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

                    bool edgeKnown = hasEdgeBetween(curr_id, new_target_id);

                    if (!edgeKnown)
                    {
                        // Synthetic dispatchers returning to their continuation get SYNTHETIC_RETURN;
                        // all other resolved targets keep CONTROL_FLOW.
                        auto edgeTy = IsSynthetic(curr_id)
                                          ? Edge::Type::SYNTHETIC_RETURN
                                          : Edge::Type::CONTROL_FLOW;
                        Edges.insert(Edge{curr_id, new_target_id, edgeTy});
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
                            reproveSubtree(new_target_id);
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

                    // Dedup: if this (source, dest_addr) pair already has a synthetic block,
                    // skip creating a new one. This can happen when a block is re-analysed
                    // during reproving after a new predecessor edge is added.
                    auto ext_key = std::make_pair(curr_id, target.Dest);
                    if (ExternalSyntheticIndex.count(ext_key))
                    {
                        // TODO: Optionally refine CalleeInfo if the new resolution is more specific.
                        break;
                    }

                    bb_id_t dispatcher_id = NextSyntheticID++;

                    SyntheticBlocks[dispatcher_id] = SyntheticBlockInfo{
                        .Type = SyntheticBlockInfo::Type::EXTERNAL,
                        .DestAddr = target.Dest,
                        .CalleeInfo = target.CalleeInfo};

                    ExternalSyntheticIndex[ext_key] = dispatcher_id;
                    Edges.insert(Edge{curr_id, dispatcher_id, Edge::Type::SYNTHETIC_EXTERNAL});

                    Worklist.push_back(dispatcher_id);
                }
                break;
                }
            }

            if (targets_result.IndirectTarget)
            {
                // Dedup: a BB can have at most one indirect outgoing edge. If one was
                // already created during a previous pass, skip re-creating it.
                if (IndirectSyntheticIndex.count(curr_id))
                {
                    // TODO: Optionally refine CalleeInfo if the new resolution is more specific.
                }
                else
                {
                    bb_id_t dispatcher_id = NextSyntheticID++;

                    SyntheticBlocks[dispatcher_id] = SyntheticBlockInfo{
                        .Type = SyntheticBlockInfo::Type::INDIRECT,
                        .DestAddr = std::nullopt,
                        .CalleeInfo = targets_result.IndirectTarget};

                    IndirectSyntheticIndex[curr_id] = dispatcher_id;
                    Edges.insert(Edge{curr_id, dispatcher_id, Edge::Type::SYNTHETIC_INDIRECT});

                    Worklist.push_back(dispatcher_id);
                }
            }
        }

        // Finished. Build final CFG.
        // TODO: extract only needed blocks / code into seperate module to return back.
        auto M = llvm::CloneModule(*CleanModule);

        helpers::link_state_utils(M.get());

        std::set<Edge> reachable_edges;
        std::set<LiftedBB> reachable_blocks;

        llvm::Function *FinalFunc = buildForwardCFG(M.get(), entry_rva, "__lifted_rebuilt_cfg", InstrumentBasicBlockEntry,
                                                    &reachable_edges, &reachable_blocks);

        return LiftResult{
            .Module = std::move(M),
            .LiftedFunction = FinalFunc,
            .Edges = reachable_edges,
            .BasicBlocks = reachable_blocks};
    }
}