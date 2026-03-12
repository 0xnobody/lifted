#include "state_fold.hpp"

#include "abi_utils.hpp"

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <cassert>
#include <optional>
#include <string>

namespace lifted::abi
{

namespace
{
    llvm::Error make_state_fold_error(const llvm::Function &F, const std::string &message)
    {
        return llvm::make_error<llvm::StringError>(
            "function '" + F.getName().str() + "': " + message,
            llvm::inconvertibleErrorCode());
    }

    llvm::StructType *getStateType(llvm::Module &M)
    {
        if (auto *G = M.getGlobalVariable("__remill_state"))
            if (auto *ST = llvm::dyn_cast<llvm::StructType>(G->getValueType()))
                return ST;
        if (auto *ST = llvm::StructType::getTypeByName(M.getContext(), "struct.State"))
            return ST;
        llvm_unreachable("Cannot find State type — link state-utils before fold/unfold");
    }

    bool tryInlineCall(llvm::CallBase &CB)
    {
        llvm::Function *Callee = CB.getCalledFunction();
        if (!Callee || Callee->isDeclaration())
            return false;
        llvm::InlineFunctionInfo IFI;
        auto Result = llvm::InlineFunction(CB, IFI);
        return Result.isSuccess();
    }

    llvm::Expected<bool> infer_folded_byval(const llvm::Function &F)
    {
        if (F.arg_empty())
            return make_state_fold_error(F, "folded state function must have a State parameter");
        if (!F.getArg(0)->getType()->isPointerTy())
            return make_state_fold_error(F, "folded state parameter must be a pointer");
        return F.hasParamAttribute(0, llvm::Attribute::ByVal);
    }

    llvm::Expected<bool> infer_unfolded_byval(const llvm::Function &F,
                                              const CallingConvention &CC)
    {
        auto UnfoldRegs = CC.getUnfoldRegisters();
        if (UnfoldRegs.empty())
            return make_state_fold_error(F, "cannot infer unfolded state passing for ABI with no unfold registers");
        if (F.arg_size() < UnfoldRegs.size())
            return make_state_fold_error(F, "unfolded function has fewer arguments than ABI unfold register count");

        std::optional<bool> IsByVal;
        for (unsigned i = 0; i < UnfoldRegs.size(); ++i)
        {
            llvm::Type *Ty = F.getArg(i)->getType();
            bool ThisIsByVal = false;
            if (Ty->isIntegerTy(64))
                ThisIsByVal = true;
            else if (Ty->isPointerTy())
                ThisIsByVal = false;
            else
                return make_state_fold_error(F, "unfolded register parameters must be either i64 values or pointers");

            if (!IsByVal.has_value())
            {
                IsByVal = ThisIsByVal;
                continue;
            }
            if (*IsByVal != ThisIsByVal)
                return make_state_fold_error(F, "unfolded register parameters mix byval and byptr forms");
        }

        return *IsByVal;
    }

    llvm::Expected<annotation_id_t> require_form(const llvm::Function &F,
                                                 state_form_t expected)
    {
        if (auto err = require_lifted_state_attrs(F))
            return std::move(err);

        auto form_or = get_state_form(F);
        if (!form_or)
            return form_or.takeError();
        if (*form_or != expected)
        {
            return make_state_fold_error(
                F,
                std::string("expected lifted.state_form='") + to_string(expected).str() +
                    "' but found '" + to_string(*form_or).str() + "'");
        }

        return get_annotation_id(F);
    }


    llvm::Expected<const CallingConvention *> resolve_function_cc_from_binary_context(
        const llvm::Function &F,
        const lifted::BinaryContext &bin_ctx)
    {
        if (auto err = require_lifted_state_attrs(F))
        {
            return make_state_fold_error(
                F,
                "BinaryContext calling convention lookup failed while reading lifted state attrs: " +
                    llvm::toString(std::move(err)));
        }

        auto annotation_id_or = get_annotation_id(F);
        if (!annotation_id_or)
        {
            return make_state_fold_error(
                F,
                "BinaryContext calling convention lookup failed while reading lifted.annotation_id: " +
                    llvm::toString(annotation_id_or.takeError()));
        }

        const auto annotation_id = *annotation_id_or;
        const auto *annotation = bin_ctx.get_by_id(annotation_id);
        if (!annotation)
        {
            return make_state_fold_error(
                F,
                "BinaryContext annotation lookup failed for lifted.annotation_id=" +
                    std::to_string(annotation_id.value));
        }
        if (!annotation->cc)
        {
            return make_state_fold_error(
                F,
                "BinaryContext annotation lookup returned null calling convention for lifted.annotation_id=" +
                    std::to_string(annotation_id.value));
        }
        return annotation->cc;
    }


    llvm::Error validate_existing_peer(const llvm::Function &existing,
                                       state_form_t expected_form,
                                       annotation_id_t expected_annotation)
    {
        auto form_or = get_state_form(existing);
        if (!form_or)
            return form_or.takeError();
        if (*form_or != expected_form)
        {
            return make_state_fold_error(
                existing,
                std::string("existing peer has unexpected lifted.state_form='") +
                    to_string(*form_or).str() + "'");
        }

        auto annotation_or = get_annotation_id(existing);
        if (!annotation_or)
            return annotation_or.takeError();
        if (*annotation_or != expected_annotation)
        {
            return make_state_fold_error(existing,
                                         "existing peer has mismatched lifted.annotation_id");
        }
        return llvm::Error::success();
    }

    llvm::Error collect_caller_callsites(llvm::Function *Target,
                                         state_form_t caller_form,
                                         llvm::SmallVectorImpl<llvm::CallBase *> &CallSites)
    {
        for (auto *U : Target->users())
        {
            auto *CB = llvm::dyn_cast<llvm::CallBase>(U);
            if (!CB)
                continue;

            llvm::Function *Caller = CB->getFunction();
            if (!Caller)
                continue;

            if (has_lifted_state_attrs(*Caller))
            {
                auto form_or = get_state_form(*Caller);
                if (!form_or)
                    return form_or.takeError();
                if (*form_or == caller_form)
                    CallSites.push_back(CB);
                continue;
            }

            if (is_state_attr_candidate(*Caller))
            {
                return make_state_fold_error(
                    *Caller,
                    std::string("calls lifted-state function '") + Target->getName().str() +
                        "' but is missing lifted state attrs");
            }
        }
        return llvm::Error::success();
    }

    llvm::FunctionType *buildUnfoldedFunctionType(llvm::LLVMContext &Ctx,
                                                  const CallingConvention &CC,
                                                  llvm::FunctionType *OrigTy,
                                                  bool isByVal)
    {
        llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Ctx);
        llvm::Type *PtrTy   = llvm::PointerType::getUnqual(Ctx);
        llvm::Type *RegTy   = isByVal ? Int64Ty : PtrTy;

        llvm::SmallVector<llvm::Type *, 16> Params;
        for (size_t i = 0, n = CC.getUnfoldRegisters().size(); i < n; ++i)
            Params.push_back(RegTy);
        for (unsigned i = 1; i < OrigTy->getNumParams(); ++i)
            Params.push_back(OrigTy->getParamType(i));

        return llvm::FunctionType::get(OrigTy->getReturnType(), Params, OrigTy->isVarArg());
    }

    llvm::FunctionType *buildFoldedFunctionType(llvm::LLVMContext &Ctx,
                                                const CallingConvention &CC,
                                                llvm::FunctionType *UnfoldedTy)
    {
        llvm::Type *PtrTy = llvm::PointerType::getUnqual(Ctx);
        llvm::SmallVector<llvm::Type *, 16> Params;
        Params.push_back(PtrTy);
        auto NumRegs = CC.getUnfoldRegisters().size();
        for (unsigned i = static_cast<unsigned>(NumRegs); i < UnfoldedTy->getNumParams(); ++i)
            Params.push_back(UnfoldedTy->getParamType(i));
        return llvm::FunctionType::get(UnfoldedTy->getReturnType(), Params, UnfoldedTy->isVarArg());
    }

    llvm::Error set_form_with_copied_function_attrs(const llvm::Function &src,
                                                 llvm::Function &dst,
                                                 state_form_t form)
    {
        auto SrcAttrs = src.getAttributes();
        // Fold/unfold peers change parameter lists, so only copy function/return
        // attrs here. Param attrs are rebuilt explicitly by the transform.
        dst.setAttributes(llvm::AttributeList::get(
            dst.getContext(), SrcAttrs.getFnAttrs(), SrcAttrs.getRetAttrs(), {}));
        return set_state_form(dst, form);
    }

    llvm::Expected<llvm::Function *> unfold_recursive_impl(
        llvm::Function *F,
        const CallingConvention &CC,
        const std::function<llvm::Expected<const CallingConvention *>(llvm::Function &)> &resolve_cc,
        llvm::SmallPtrSet<llvm::Function *, 16> &Visited)
    {
        if (!Visited.insert(F).second)
            return F;

        llvm::SmallVector<llvm::Function *, 8> Callees;
        if (!F->isDeclaration())
        {
            llvm::SmallPtrSet<llvm::Function *, 8> SeenCallees;
            for (auto &BB : *F)
            {
                for (auto &I : BB)
                {
                    auto *CB = llvm::dyn_cast<llvm::CallBase>(&I);
                    if (!CB)
                        continue;
                    auto *Callee = CB->getCalledFunction();
                    if (!Callee)
                        continue;
                    if (!is_state_attr_candidate(*Callee))
                        continue;
                    if (!SeenCallees.insert(Callee).second)
                        continue;
                    if (!has_lifted_state_attrs(*Callee))
                    {
                        return make_state_fold_error(
                            *Callee,
                            "recursive unfold encountered stateful callee without lifted state attrs");
                    }
                    auto form_or = get_state_form(*Callee);
                    if (!form_or)
                        return form_or.takeError();
                    if (*form_or == state_form_t::folded && !Visited.count(Callee))
                        Callees.push_back(Callee);
                }
            }
        }

        for (auto *Callee : Callees)
        {
            auto callee_cc_or = resolve_cc(*Callee);
            if (!callee_cc_or)
                return callee_cc_or.takeError();
            auto CalleeOr = unfold_recursive_impl(Callee, **callee_cc_or, resolve_cc, Visited);
            if (!CalleeOr)
                return CalleeOr.takeError();
        }

        return unfold_function_state(F, CC);
    }

    llvm::Expected<llvm::Function *> fold_recursive_impl(
        llvm::Function *F,
        const CallingConvention &CC,
        const std::function<llvm::Expected<const CallingConvention *>(llvm::Function &)> &resolve_cc,
        llvm::SmallPtrSet<llvm::Function *, 16> &Visited)
    {
        if (!Visited.insert(F).second)
            return F;

        llvm::SmallVector<llvm::Function *, 8> Callees;
        if (!F->isDeclaration())
        {
            llvm::SmallPtrSet<llvm::Function *, 8> SeenCallees;
            for (auto &BB : *F)
            {
                for (auto &I : BB)
                {
                    auto *CB = llvm::dyn_cast<llvm::CallBase>(&I);
                    if (!CB)
                        continue;
                    auto *Callee = CB->getCalledFunction();
                    if (!Callee)
                        continue;
                    if (!is_state_attr_candidate(*Callee))
                        continue;
                    if (!SeenCallees.insert(Callee).second)
                        continue;
                    if (!has_lifted_state_attrs(*Callee))
                    {
                        return make_state_fold_error(
                            *Callee,
                            "recursive fold encountered stateful callee without lifted state attrs");
                    }
                    auto form_or = get_state_form(*Callee);
                    if (!form_or)
                        return form_or.takeError();
                    if (*form_or == state_form_t::unfolded && !Visited.count(Callee))
                        Callees.push_back(Callee);
                }
            }
        }

        for (auto *Callee : Callees)
        {
            auto callee_cc_or = resolve_cc(*Callee);
            if (!callee_cc_or)
                return callee_cc_or.takeError();
            auto CalleeOr = fold_recursive_impl(Callee, **callee_cc_or, resolve_cc, Visited);
            if (!CalleeOr)
                return CalleeOr.takeError();
        }

        return fold_function_state(F, CC);
    }
} // namespace

    bool is_unfolded_function(const llvm::Function *F)
    {
        if (!F)
            return false;
        auto form_or = get_state_form(*F);
        return form_or && *form_or == state_form_t::unfolded;
    }

    bool is_folded_function(const llvm::Function *F)
    {
        if (!F)
            return false;
        auto form_or = get_state_form(*F);
        return form_or && *form_or == state_form_t::folded;
    }

    bool is_byval_state(const llvm::Function *F)
    {
        if (!F)
            return false;
        if (is_unfolded_function(F))
        {
            if (F->arg_empty())
                return false;
            return F->getArg(0)->getType()->isIntegerTy(64);
        }
        if (F->arg_empty())
            return false;
        return F->hasParamAttribute(0, llvm::Attribute::ByVal);
    }

    llvm::Argument *getRegisterArgument(llvm::Function *F,
                                        const CallingConvention &CC,
                                        ABIRegister Reg)
    {
        auto idx = CC.getUnfoldParamIndex(Reg);
        if (!idx.has_value())
            return nullptr;
        return F->getArg(*idx);
    }

    bool isRegisterParamByPointer(const llvm::Function *F)
    {
        return F && is_unfolded_function(F) && !F->arg_empty() && F->getArg(0)->getType()->isPointerTy();
    }

    llvm::Expected<llvm::Function *> unfold_function_state(llvm::Function *F,
                                                           const CallingConvention &CC)
    {
        auto annotation_or = require_form(*F, state_form_t::folded);
        if (!annotation_or)
            return annotation_or.takeError();

        auto isByValOr = infer_folded_byval(*F);
        if (!isByValOr)
            return isByValOr.takeError();

        llvm::Module *M = F->getParent();
        llvm::LLVMContext &Ctx = M->getContext();
        llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Ctx);
        auto UnfoldRegs = CC.getUnfoldRegisters();
        auto *StateTy = getStateType(*M);
        const bool isByVal = *isByValOr;

        std::string UnfoldedName = F->getName().str() + ".unfolded";
        if (auto *Existing = M->getFunction(UnfoldedName))
        {
            if (auto err = validate_existing_peer(*Existing, state_form_t::unfolded, *annotation_or))
                return std::move(err);
            return Existing;
        }

        auto *UnfoldedTy = buildUnfoldedFunctionType(Ctx, CC, F->getFunctionType(), isByVal);
        auto *Unfolded = llvm::Function::Create(
            UnfoldedTy, llvm::GlobalValue::InternalLinkage, UnfoldedName, M);
        if (auto err = set_form_with_copied_function_attrs(*F, *Unfolded, state_form_t::unfolded))
            return std::move(err);

        unsigned ArgIdx = 0;
        for (auto Reg : UnfoldRegs)
            Unfolded->getArg(ArgIdx++)->setName(getExtractHelperName(Reg).drop_front(10));
        for (unsigned i = 1, n = F->arg_size(); i < n; ++i, ++ArgIdx)
            Unfolded->getArg(ArgIdx)->setName(F->getArg(i)->getName());

        auto *Entry = llvm::BasicBlock::Create(Ctx, "entry", Unfolded);
        llvm::IRBuilder<> B(Entry);

        auto *StateAlloca = B.CreateAlloca(StateTy, nullptr, "state");
        B.CreateStore(llvm::Constant::getNullValue(StateTy), StateAlloca);

        ArgIdx = 0;
        for (auto Reg : UnfoldRegs)
        {
            llvm::Value *RegArg = Unfolded->getArg(ArgIdx++);
            llvm::Value *RegVal = isByVal
                                      ? RegArg
                                      : B.CreateLoad(Int64Ty, RegArg, "reg");
            StoreRegister(B, Reg, StateAlloca, RegVal);
        }

        llvm::SmallVector<llvm::Value *, 8> InnerArgs;
        InnerArgs.push_back(StateAlloca);
        for (unsigned i = static_cast<unsigned>(UnfoldRegs.size()); i < Unfolded->arg_size(); ++i)
            InnerArgs.push_back(Unfolded->getArg(i));

        auto *InnerCall = B.CreateCall(F->getFunctionType(), F, InnerArgs);
        if (isByVal)
            InnerCall->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));

        if (!isByVal)
        {
            ArgIdx = 0;
            for (auto Reg : UnfoldRegs)
            {
                llvm::Value *Updated = ExtractRegister(B, Reg, StateAlloca);
                B.CreateStore(Updated, Unfolded->getArg(ArgIdx++));
            }
        }

        if (UnfoldedTy->getReturnType()->isVoidTy())
            B.CreateRetVoid();
        else
            B.CreateRet(InnerCall);

        if (!F->isDeclaration())
            tryInlineCall(*InnerCall);

        llvm::SmallVector<llvm::CallBase *, 8> CallSites;
        if (auto err = collect_caller_callsites(F, state_form_t::folded, CallSites))
            return std::move(err);

        for (auto *CB : CallSites)
        {
            auto *CallerM = CB->getFunction()->getParent();
            std::string StubName = F->getName().str() + ".unfold.stub." +
                                   std::to_string(reinterpret_cast<uintptr_t>(CB));
            auto *StubFn = llvm::Function::Create(
                F->getFunctionType(), llvm::GlobalValue::InternalLinkage, StubName, CallerM);
            StubFn->addFnAttr(llvm::Attribute::AlwaysInline);
            if (isByVal)
                StubFn->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));

            auto *StubEntry = llvm::BasicBlock::Create(Ctx, "entry", StubFn);
            llvm::IRBuilder<> SB(StubEntry);

            llvm::Value *StubStateArg = StubFn->getArg(0);
            llvm::SmallVector<llvm::Value *, 16> UnfoldCallArgs;

            if (isByVal)
            {
                for (auto Reg : UnfoldRegs)
                    UnfoldCallArgs.push_back(ExtractRegister(SB, Reg, StubStateArg));
            }
            else
            {
                for (auto Reg : UnfoldRegs)
                {
                    auto *A = SB.CreateAlloca(Int64Ty, nullptr,
                                              getExtractHelperName(Reg).drop_front(10));
                    SB.CreateStore(ExtractRegister(SB, Reg, StubStateArg), A);
                    UnfoldCallArgs.push_back(A);
                }
            }

            for (unsigned i = 1, n = StubFn->arg_size(); i < n; ++i)
                UnfoldCallArgs.push_back(StubFn->getArg(i));

            auto *UnfoldedCall = SB.CreateCall(Unfolded->getFunctionType(), Unfolded, UnfoldCallArgs);

            if (!isByVal)
            {
                for (unsigned i = 0; i < UnfoldRegs.size(); ++i)
                {
                    llvm::Value *Updated = SB.CreateLoad(Int64Ty, UnfoldCallArgs[i]);
                    StoreRegister(SB, UnfoldRegs[i], StubStateArg, Updated);
                }
            }

            if (StubFn->getReturnType()->isVoidTy())
                SB.CreateRetVoid();
            else
                SB.CreateRet(UnfoldedCall);

            llvm::SmallVector<llvm::Value *, 8> CBArgs(CB->args());
            llvm::IRBuilder<> RB(CB);
            auto *StubCall = RB.CreateCall(StubFn->getFunctionType(), StubFn, CBArgs);
            if (isByVal)
                StubCall->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));
            if (CB->hasName())
                StubCall->setName(CB->getName());
            CB->replaceAllUsesWith(StubCall);
            CB->eraseFromParent();

            tryInlineCall(*StubCall);
            if (StubFn->use_empty())
                StubFn->eraseFromParent();
        }

        return Unfolded;
    }

    llvm::Expected<llvm::Function *> fold_function_state(llvm::Function *F,
                                                         const CallingConvention &CC)
    {
        auto annotation_or = require_form(*F, state_form_t::unfolded);
        if (!annotation_or)
            return annotation_or.takeError();

        auto isByValOr = infer_unfolded_byval(*F, CC);
        if (!isByValOr)
            return isByValOr.takeError();

        llvm::Module *M = F->getParent();
        llvm::LLVMContext &Ctx = M->getContext();
        llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Ctx);
        auto UnfoldRegs = CC.getUnfoldRegisters();
        auto *StateTy = getStateType(*M);
        auto NumRegs = static_cast<unsigned>(UnfoldRegs.size());
        const bool isByVal = *isByValOr;

        std::string OrigName = F->getName().str();
        std::string FoldedName;
        const std::string kUnfoldedSuffix = ".unfolded";
        if (OrigName.size() > kUnfoldedSuffix.size() &&
            OrigName.compare(OrigName.size() - kUnfoldedSuffix.size(),
                             kUnfoldedSuffix.size(), kUnfoldedSuffix) == 0)
            FoldedName = OrigName.substr(0, OrigName.size() - kUnfoldedSuffix.size()) + ".folded";
        else
            FoldedName = OrigName + ".folded";

        if (auto *Existing = M->getFunction(FoldedName))
        {
            if (auto err = validate_existing_peer(*Existing, state_form_t::folded, *annotation_or))
                return std::move(err);
            return Existing;
        }

        auto *FoldedTy = buildFoldedFunctionType(Ctx, CC, F->getFunctionType());
        auto *Folded = llvm::Function::Create(
            FoldedTy, llvm::GlobalValue::InternalLinkage, FoldedName, M);
        if (auto err = set_form_with_copied_function_attrs(*F, *Folded, state_form_t::folded))
            return std::move(err);
        if (isByVal)
            Folded->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));

        Folded->getArg(0)->setName("state");
        for (unsigned i = 1; i < FoldedTy->getNumParams(); ++i)
        {
            unsigned UnfIdx = NumRegs + (i - 1);
            if (UnfIdx < F->arg_size())
                Folded->getArg(i)->setName(F->getArg(UnfIdx)->getName());
        }

        auto *Entry = llvm::BasicBlock::Create(Ctx, "entry", Folded);
        llvm::IRBuilder<> B(Entry);

        llvm::Value *StateArg = Folded->getArg(0);
        llvm::SmallVector<llvm::Value *, 16> UnfoldCallArgs;

        if (isByVal)
        {
            for (auto Reg : UnfoldRegs)
                UnfoldCallArgs.push_back(ExtractRegister(B, Reg, StateArg));
        }
        else
        {
            for (auto Reg : UnfoldRegs)
            {
                auto *A = B.CreateAlloca(Int64Ty, nullptr,
                                         getExtractHelperName(Reg).drop_front(10));
                B.CreateStore(ExtractRegister(B, Reg, StateArg), A);
                UnfoldCallArgs.push_back(A);
            }
        }

        for (unsigned i = 1; i < FoldedTy->getNumParams(); ++i)
            UnfoldCallArgs.push_back(Folded->getArg(i));

        auto *UnfoldedCall = B.CreateCall(F->getFunctionType(), F, UnfoldCallArgs);

        if (!isByVal)
        {
            for (unsigned i = 0; i < NumRegs; ++i)
            {
                llvm::Value *Updated = B.CreateLoad(Int64Ty, UnfoldCallArgs[i]);
                StoreRegister(B, UnfoldRegs[i], StateArg, Updated);
            }
        }

        if (FoldedTy->getReturnType()->isVoidTy())
            B.CreateRetVoid();
        else
            B.CreateRet(UnfoldedCall);

        if (!F->isDeclaration())
            tryInlineCall(*UnfoldedCall);

        llvm::SmallVector<llvm::CallBase *, 8> CallSites;
        if (auto err = collect_caller_callsites(F, state_form_t::unfolded, CallSites))
            return std::move(err);

        for (auto *CB : CallSites)
        {
            auto *CallerM = CB->getFunction()->getParent();
            std::string StubName = F->getName().str() + ".fold.stub." +
                                   std::to_string(reinterpret_cast<uintptr_t>(CB));
            auto *StubFn = llvm::Function::Create(
                F->getFunctionType(), llvm::GlobalValue::InternalLinkage, StubName, CallerM);
            StubFn->addFnAttr(llvm::Attribute::AlwaysInline);

            auto *StubEntry = llvm::BasicBlock::Create(Ctx, "entry", StubFn);
            llvm::IRBuilder<> SB(StubEntry);

            auto *StubStateAlloca = SB.CreateAlloca(StateTy, nullptr, "state");
            SB.CreateStore(llvm::Constant::getNullValue(StateTy), StubStateAlloca);

            if (isByVal)
            {
                for (unsigned i = 0; i < NumRegs; ++i)
                    StoreRegister(SB, UnfoldRegs[i], StubStateAlloca, StubFn->getArg(i));
            }
            else
            {
                for (unsigned i = 0; i < NumRegs; ++i)
                {
                    llvm::Value *V = SB.CreateLoad(Int64Ty, StubFn->getArg(i));
                    StoreRegister(SB, UnfoldRegs[i], StubStateAlloca, V);
                }
            }

            llvm::SmallVector<llvm::Value *, 8> FoldedCallArgs;
            FoldedCallArgs.push_back(StubStateAlloca);
            for (unsigned i = NumRegs; i < StubFn->arg_size(); ++i)
                FoldedCallArgs.push_back(StubFn->getArg(i));

            auto *FoldedCall = SB.CreateCall(Folded->getFunctionType(), Folded, FoldedCallArgs);
            if (isByVal)
                FoldedCall->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));

            if (!isByVal)
            {
                for (unsigned i = 0; i < NumRegs; ++i)
                {
                    llvm::Value *Updated = ExtractRegister(SB, UnfoldRegs[i], StubStateAlloca);
                    SB.CreateStore(Updated, StubFn->getArg(i));
                }
            }

            if (StubFn->getReturnType()->isVoidTy())
                SB.CreateRetVoid();
            else
                SB.CreateRet(FoldedCall);

            llvm::SmallVector<llvm::Value *, 8> CBArgs(CB->args());
            llvm::IRBuilder<> RB(CB);
            auto *StubCall = RB.CreateCall(StubFn->getFunctionType(), StubFn, CBArgs);
            if (CB->hasName())
                StubCall->setName(CB->getName());
            CB->replaceAllUsesWith(StubCall);
            CB->eraseFromParent();

            tryInlineCall(*StubCall);
            if (StubFn->use_empty())
                StubFn->eraseFromParent();
        }

        return Folded;
    }

    llvm::Expected<llvm::Function *> unfold_function_state(llvm::Function *F,
                                                           const lifted::BinaryContext &bin_ctx)
    {
        auto cc_or = resolve_function_cc_from_binary_context(*F, bin_ctx);
        if (!cc_or)
            return cc_or.takeError();
        return unfold_function_state(F, **cc_or);
    }

    llvm::Expected<llvm::Function *> fold_function_state(llvm::Function *F,
                                                         const lifted::BinaryContext &bin_ctx)
    {
        auto cc_or = resolve_function_cc_from_binary_context(*F, bin_ctx);
        if (!cc_or)
            return cc_or.takeError();
        return fold_function_state(F, **cc_or);
    }


    llvm::Expected<llvm::Function *> unfold_function_state_recursive(
        llvm::Function *F,
        const CallingConvention &CC,
        std::function<llvm::Expected<const CallingConvention *>(llvm::Function &)> resolve_cc)
    {
        if (auto annotation_or = require_form(*F, state_form_t::folded); !annotation_or)
            return annotation_or.takeError();

        llvm::SmallPtrSet<llvm::Function *, 16> Visited;
        return unfold_recursive_impl(F, CC, resolve_cc, Visited);
    }

    llvm::Expected<llvm::Function *> unfold_function_state_recursive(
        llvm::Function *F,
        const lifted::BinaryContext &bin_ctx)
    {
        auto cc_or = resolve_function_cc_from_binary_context(*F, bin_ctx);
        if (!cc_or)
            return cc_or.takeError();

        auto resolve_cc = [&](llvm::Function &Fn) -> llvm::Expected<const CallingConvention *> {
            return resolve_function_cc_from_binary_context(Fn, bin_ctx);
        };

        return unfold_function_state_recursive(F, **cc_or, resolve_cc);
    }

    llvm::Expected<llvm::Function *> fold_function_state_recursive(
        llvm::Function *F,
        const CallingConvention &CC,
        std::function<llvm::Expected<const CallingConvention *>(llvm::Function &)> resolve_cc)
    {
        if (auto annotation_or = require_form(*F, state_form_t::unfolded); !annotation_or)
            return annotation_or.takeError();

        llvm::SmallPtrSet<llvm::Function *, 16> Visited;
        return fold_recursive_impl(F, CC, resolve_cc, Visited);
    }

    llvm::Expected<llvm::Function *> fold_function_state_recursive(
        llvm::Function *F,
        const lifted::BinaryContext &bin_ctx)
    {
        auto cc_or = resolve_function_cc_from_binary_context(*F, bin_ctx);
        if (!cc_or)
            return cc_or.takeError();

        auto resolve_cc = [&](llvm::Function &Fn) -> llvm::Expected<const CallingConvention *> {
            return resolve_function_cc_from_binary_context(Fn, bin_ctx);
        };

        return fold_function_state_recursive(F, **cc_or, resolve_cc);
    }

} // namespace lifted::abi
