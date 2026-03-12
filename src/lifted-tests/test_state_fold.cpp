#include "test_framework.hpp"

#include "abi/all_registers_cc.hpp"
#include "abi/calling_convention.hpp"
#include "abi/function_state_attrs.hpp"
#include "abi/state_fold.hpp"
#include "abi/systemv_x64.hpp"

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Error.h>

#include <memory>
#include <string>

using namespace lifted;
using namespace lifted::abi;

namespace
{
    void checkSuccess(llvm::Error Err)
    {
        if (Err)
        {
            auto Msg = llvm::toString(std::move(Err));
            CHECK(false && "unexpected llvm::Error");
            (void)Msg;
        }
    }

    template <typename T>
    T unwrapExpected(llvm::Expected<T> Value)
    {
        if (!Value)
        {
            auto Msg = llvm::toString(Value.takeError());
            CHECK(false && "unexpected llvm::Expected failure");
            (void)Msg;
            return T{};
        }
        return *Value;
    }

    template <typename T>
    std::string takeExpectedError(llvm::Expected<T> Value)
    {
        CHECK(!Value);
        return llvm::toString(Value.takeError());
    }

    std::unique_ptr<LIEF::Binary> makeMockBinary()
    {
#ifdef EVAL_TWO_FUNCS_SO
        auto binary = LIEF::Parser::parse(EVAL_TWO_FUNCS_SO);
#else
        auto binary = LIEF::Parser::parse("/bin/true");
#endif
        CHECK(binary != nullptr);
        return binary;
    }

    struct MockModule
    {
        llvm::LLVMContext Ctx;
        std::unique_ptr<llvm::Module> M;
        BinaryContext BinCtx;
        llvm::StructType *StateTy = nullptr;
        llvm::Type *Int64Ty = nullptr;
        llvm::Type *PtrTy = nullptr;
        llvm::Type *VoidTy = nullptr;

        explicit MockModule(const char *Name = "test")
            : BinCtx(makeMockBinary())
        {
            M = std::make_unique<llvm::Module>(Name, Ctx);

            Int64Ty = llvm::Type::getInt64Ty(Ctx);
            PtrTy   = llvm::PointerType::getUnqual(Ctx);
            VoidTy  = llvm::Type::getVoidTy(Ctx);

            StateTy = llvm::StructType::create(Ctx, "struct.State");
            llvm::SmallVector<llvm::Type *, 16> Fields(16, Int64Ty);
            StateTy->setBody(Fields, false);

            new llvm::GlobalVariable(*M, StateTy, false,
                                     llvm::GlobalValue::ExternalLinkage,
                                     nullptr, "__remill_state");

            declareRegisterHelpers(SystemVx64CC::get().getVolatileRegisters());
        }

        void declareRegisterHelpers(llvm::ArrayRef<ABIRegister> Regs)
        {
            auto *ExtTy = llvm::FunctionType::get(Int64Ty, {PtrTy}, false);
            auto *StTy  = llvm::FunctionType::get(VoidTy, {PtrTy, Int64Ty}, false);
            for (auto Reg : Regs)
            {
                M->getOrInsertFunction(getExtractHelperName(Reg), ExtTy);
                M->getOrInsertFunction(getStoreHelperName(Reg), StTy);
            }
        }

        annotation_id_t annotate(llvm::Function *F, state_form_t Form)
        {
            auto Ann = std::make_unique<fnc_annotation_t>();
            Ann->name = F->getName().str();
            Ann->cc = &CC();
            annotation_id_t Id = BinCtx.add_annotation(std::move(Ann));
            checkSuccess(set_state_form(*F, Form));
            checkSuccess(set_annotation_id(*F, Id));
            return Id;
        }

        llvm::Function *makeFolded(const std::string &Name,
                                   bool withBody = true,
                                   bool annotate_fn = true)
        {
            auto *Ty = llvm::FunctionType::get(PtrTy, {PtrTy, Int64Ty, PtrTy}, false);
            auto *F = llvm::Function::Create(Ty, llvm::GlobalValue::ExternalLinkage, Name, *M);
            F->getArg(0)->setName("state");
            F->getArg(1)->setName("addr");
            F->getArg(2)->setName("mem");
            if (annotate_fn)
                annotate(F, state_form_t::folded);
            if (withBody)
                addTrivialBody(F);
            return F;
        }

        llvm::Function *makeByvalFolded(const std::string &Name,
                                        bool withBody = true,
                                        bool annotate_fn = true)
        {
            auto *F = makeFolded(Name, withBody, annotate_fn);
            F->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));
            return F;
        }

        llvm::Function *makeUnfoldedShell(const std::string &Name,
                                          bool isByVal,
                                          bool annotate_fn = true)
        {
            llvm::SmallVector<llvm::Type *, 16> Params;
            llvm::Type *RegTy = isByVal ? Int64Ty : PtrTy;
            for (size_t i = 0; i < CC().getUnfoldRegisters().size(); ++i)
                Params.push_back(RegTy);
            Params.push_back(Int64Ty);
            Params.push_back(PtrTy);

            auto *Ty = llvm::FunctionType::get(PtrTy, Params, false);
            auto *F = llvm::Function::Create(Ty, llvm::GlobalValue::InternalLinkage, Name, *M);
            unsigned ArgIdx = 0;
            for (auto Reg : CC().getUnfoldRegisters())
                F->getArg(ArgIdx++)->setName(getExtractHelperName(Reg).drop_front(10));
            F->getArg(ArgIdx++)->setName("addr");
            F->getArg(ArgIdx)->setName("mem");
            if (annotate_fn)
                annotate(F, state_form_t::unfolded);
            addTrivialBody(F);
            return F;
        }

        void setBodyToCallFn(llvm::Function *Caller,
                             llvm::Function *Callee,
                             bool addByValOnArg0 = false)
        {
            while (!Caller->empty())
                Caller->getEntryBlock().eraseFromParent();

            auto *Entry = llvm::BasicBlock::Create(Ctx, "entry", Caller);
            llvm::IRBuilder<> B(Entry);
            llvm::SmallVector<llvm::Value *, 8> Args;
            for (auto &A : Caller->args())
                Args.push_back(&A);
            auto *Ret = B.CreateCall(Callee->getFunctionType(), Callee, Args);
            if (addByValOnArg0)
                Ret->addParamAttr(0, llvm::Attribute::getWithByValType(Ctx, StateTy));
            B.CreateRet(Ret);
        }

        const CallingConvention &CC() const { return SystemVx64CC::get(); }

    private:
        void addTrivialBody(llvm::Function *F)
        {
            auto *Entry = llvm::BasicBlock::Create(Ctx, "entry", F);
            llvm::IRBuilder<> B(Entry);
            B.CreateRet(llvm::UndefValue::get(F->getReturnType()));
        }
    };

    bool bodyCallsFunction(llvm::Function *F, llvm::StringRef Name)
    {
        if (!F || F->isDeclaration())
            return false;
        for (auto &BB : *F)
            for (auto &I : BB)
                if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I))
                    if (auto *Called = CB->getCalledFunction())
                        if (Called->getName() == Name)
                            return true;
        return false;
    }
} // namespace

TEST(function_state_attrs_round_trip)
{
    MockModule MM;
    auto *F = MM.makeFolded("attrs");

    CHECK(has_state_form(*F));
    CHECK(has_annotation_id_attr(*F));
    CHECK(has_lifted_state_attrs(*F));
    CHECK(is_state_attr_candidate(*F));

    auto Form = unwrapExpected(get_state_form(*F));
    auto Annotation = unwrapExpected(get_annotation_id(*F));
    CHECK(Form == state_form_t::folded);
    CHECK_EQ(Annotation.value, 0u);

    auto *Clone = llvm::Function::Create(F->getFunctionType(),
                                         llvm::GlobalValue::InternalLinkage,
                                         "attrs_clone", *MM.M);
    copy_lifted_state_attrs(*F, *Clone);
    CHECK(unwrapExpected(get_state_form(*Clone)) == state_form_t::folded);
    CHECK_EQ(unwrapExpected(get_annotation_id(*Clone)).value, Annotation.value);
}

TEST(function_state_attrs_reject_invalid_values)
{
    MockModule MM;
    auto *Missing = MM.makeFolded("missing", true, false);
    auto MissingErr = llvm::toString(require_lifted_state_attrs(*Missing));
    CHECK(MissingErr.find("missing lifted.state_form") != std::string::npos);

    auto *BadForm = MM.makeFolded("bad_form", true, false);
    BadForm->addFnAttr("lifted.state_form", "sideways");
    checkSuccess(set_annotation_id(*BadForm, annotation_id_t{7}));
    auto BadFormErr = takeExpectedError(get_state_form(*BadForm));
    CHECK(BadFormErr.find("invalid lifted.state_form") != std::string::npos);

    auto *BadAnnotation = MM.makeFolded("bad_annotation", true, false);
    checkSuccess(set_state_form(*BadAnnotation, state_form_t::folded));
    BadAnnotation->addFnAttr("lifted.annotation_id", "nope");
    auto BadAnnotationErr = takeExpectedError(get_annotation_id(*BadAnnotation));
    CHECK(BadAnnotationErr.find("invalid lifted.annotation_id") != std::string::npos);
}

TEST(unfold_requires_explicit_attrs)
{
    MockModule MM;
    auto *Raw = MM.makeFolded("raw_folded", true, false);
    auto Err = takeExpectedError(unfold_function_state(Raw, MM.CC()));
    CHECK(Err.find("missing lifted.state_form") != std::string::npos);
}

TEST(fold_requires_explicit_attrs)
{
    MockModule MM;
    auto *Raw = MM.makeUnfoldedShell("raw_unfolded", false, false);
    auto Err = takeExpectedError(fold_function_state(Raw, MM.CC()));
    CHECK(Err.find("missing lifted.state_form") != std::string::npos);
}

TEST(binary_context_wrappers_round_trip)
{
    MockModule MM;
    auto *Original = MM.makeByvalFolded("ctx_roundtrip");
    auto Annotation = unwrapExpected(get_annotation_id(*Original));

    auto *Unfolded = unwrapExpected(unfold_function_state(Original, MM.BinCtx));
    CHECK(is_unfolded_function(Unfolded));
    CHECK_EQ(unwrapExpected(get_annotation_id(*Unfolded)).value, Annotation.value);

    auto *Folded = unwrapExpected(fold_function_state(Unfolded, MM.BinCtx));
    CHECK(is_folded_function(Folded));
    CHECK_EQ(unwrapExpected(get_annotation_id(*Folded)).value, Annotation.value);
}

TEST(binary_context_wrapper_rejects_missing_annotation)
{
    MockModule MM;
    auto *F = MM.makeFolded("ctx_missing", true, false);
    checkSuccess(set_state_form(*F, state_form_t::folded));
    checkSuccess(set_annotation_id(*F, annotation_id_t{999}));

    auto Err = takeExpectedError(unfold_function_state(F, MM.BinCtx));
    CHECK(Err.find("ctx_missing") != std::string::npos);
    CHECK(Err.find("BinaryContext annotation lookup failed") != std::string::npos);
}


TEST(unfold_basic_signature_byptr)
{
    MockModule MM;
    auto NumRegs = MM.CC().getUnfoldRegisters().size();
    auto *F = MM.makeFolded("basic_sig");

    auto *U = unwrapExpected(unfold_function_state(F, MM.CC()));
    CHECK(is_unfolded_function(U));
    CHECK(!is_folded_function(U));
    CHECK(!is_byval_state(U));
    CHECK(isRegisterParamByPointer(U));
    CHECK_EQ(U->arg_size(), NumRegs + 2u);
    for (unsigned i = 0; i < NumRegs; ++i)
        CHECK(U->getArg(i)->getType() == MM.PtrTy);
    CHECK(U->getArg(NumRegs)->getType() == MM.Int64Ty);
    CHECK(U->getArg(NumRegs + 1)->getType() == MM.PtrTy);
}

TEST(unfold_basic_signature_byval)
{
    MockModule MM;
    auto NumRegs = MM.CC().getUnfoldRegisters().size();
    auto *F = MM.makeByvalFolded("byval_sig");

    auto *U = unwrapExpected(unfold_function_state(F, MM.CC()));
    CHECK(is_unfolded_function(U));
    CHECK(is_byval_state(U));
    CHECK(!isRegisterParamByPointer(U));
    for (unsigned i = 0; i < NumRegs; ++i)
        CHECK(U->getArg(i)->getType() == MM.Int64Ty);
}

TEST(unfold_preserves_annotation_and_updates_callers)
{
    MockModule MM;
    auto *Callee = MM.makeFolded("callee");
    auto Annotation = unwrapExpected(get_annotation_id(*Callee));

    auto *Caller = MM.makeFolded("caller");
    MM.setBodyToCallFn(Caller, Callee);
    CHECK(bodyCallsFunction(Caller, "callee"));

    auto *U = unwrapExpected(unfold_function_state(Callee, MM.CC()));
    CHECK(!bodyCallsFunction(Caller, "callee"));
    CHECK(unwrapExpected(get_state_form(*U)) == state_form_t::unfolded);
    CHECK_EQ(unwrapExpected(get_annotation_id(*U)).value, Annotation.value);
    CHECK(unwrapExpected(get_state_form(*Callee)) == state_form_t::folded);
}

TEST(unfold_copies_function_attrs_to_generated_peer)
{
    MockModule MM;
    auto *F = MM.makeFolded("attr_folded");
    F->addFnAttr(llvm::Attribute::AlwaysInline);
    F->addFnAttr(llvm::Attribute::NoUnwind);

    auto *U = unwrapExpected(unfold_function_state(F, MM.CC()));
    CHECK(U->hasFnAttribute(llvm::Attribute::AlwaysInline));
    CHECK(U->hasFnAttribute(llvm::Attribute::NoUnwind));
}


TEST(unfold_declaration_keeps_forwarding_call)
{
    MockModule MM;
    auto *Decl = MM.makeFolded("decl_only", false);

    auto *U = unwrapExpected(unfold_function_state(Decl, MM.CC()));
    CHECK(U != nullptr);
    CHECK(bodyCallsFunction(U, "decl_only"));
}

TEST(get_register_argument_tracks_abi_indices)
{
    MockModule MM;
    auto *U = unwrapExpected(unfold_function_state(MM.makeFolded("reg_query"), MM.CC()));

    auto *RAX = getRegisterArgument(U, MM.CC(), ABIRegister::RAX);
    auto *RDI = getRegisterArgument(U, MM.CC(), ABIRegister::RDI);
    CHECK(RAX == U->getArg(0));
    CHECK(RDI == U->getArg(4));
    CHECK(getRegisterArgument(U, MM.CC(), ABIRegister::RBX) == nullptr);
}

TEST(fold_basic_signature_byptr)
{
    MockModule MM;
    auto *U = unwrapExpected(unfold_function_state(MM.makeFolded("fold_basic"), MM.CC()));
    auto Annotation = unwrapExpected(get_annotation_id(*U));

    auto *Folded = unwrapExpected(fold_function_state(U, MM.CC()));
    CHECK(is_folded_function(Folded));
    CHECK(!is_unfolded_function(Folded));
    CHECK(!is_byval_state(Folded));
    CHECK_EQ(Folded->arg_size(), 3u);
    CHECK(!Folded->hasParamAttribute(0, llvm::Attribute::ByVal));
    CHECK_EQ(unwrapExpected(get_annotation_id(*Folded)).value, Annotation.value);
}

TEST(fold_basic_signature_byval)
{
    MockModule MM;
    auto *U = unwrapExpected(unfold_function_state(MM.makeByvalFolded("fold_byval"), MM.CC()));
    auto *Folded = unwrapExpected(fold_function_state(U, MM.CC()));

    CHECK(is_folded_function(Folded));
    CHECK(is_byval_state(Folded));
    CHECK(Folded->hasParamAttribute(0, llvm::Attribute::ByVal));
}

TEST(fold_copies_function_attrs_to_generated_peer)
{
    MockModule MM;
    auto *U = MM.makeUnfoldedShell("attr_unfolded", false);
    U->addFnAttr(llvm::Attribute::AlwaysInline);
    U->addFnAttr(llvm::Attribute::NoUnwind);

    auto *Folded = unwrapExpected(fold_function_state(U, MM.CC()));
    CHECK(Folded->hasFnAttribute(llvm::Attribute::AlwaysInline));
    CHECK(Folded->hasFnAttribute(llvm::Attribute::NoUnwind));
}


TEST(fold_updates_unfolded_callers)
{
    MockModule MM;
    auto *Callee = MM.makeFolded("fold_callee");
    auto *U = unwrapExpected(unfold_function_state(Callee, MM.CC()));

    auto *Caller = MM.makeUnfoldedShell("fold_caller", false);
    MM.setBodyToCallFn(Caller, U);
    CHECK(bodyCallsFunction(Caller, U->getName()));

    auto *Folded = unwrapExpected(fold_function_state(U, MM.CC()));
    CHECK(Folded != nullptr);
    CHECK(!bodyCallsFunction(Caller, U->getName()));
}

TEST(repeated_round_trip_preserves_contract)
{
    MockModule MM;
    auto *Original = MM.makeByvalFolded("roundtrip");
    auto OriginalAnnotation = unwrapExpected(get_annotation_id(*Original));

    auto *U1 = unwrapExpected(unfold_function_state(Original, MM.CC()));
    auto *F1 = unwrapExpected(fold_function_state(U1, MM.CC()));
    auto *U2 = unwrapExpected(unfold_function_state(F1, MM.CC()));
    auto *F2 = unwrapExpected(fold_function_state(U2, MM.CC()));

    CHECK(is_folded_function(F2));
    CHECK(is_byval_state(F2));
    CHECK_EQ(F2->arg_size(), Original->arg_size());
    CHECK_EQ(unwrapExpected(get_annotation_id(*F2)).value, OriginalAnnotation.value);
}

TEST(recursive_unfold_chain)
{
    MockModule MM;
    auto *Leaf = MM.makeFolded("leaf");
    auto *Mid = MM.makeFolded("mid");
    auto *Root = MM.makeFolded("root");
    MM.setBodyToCallFn(Mid, Leaf);
    MM.setBodyToCallFn(Root, Mid);

    auto *RootUnfolded = unwrapExpected(unfold_function_state_recursive(Root, MM.BinCtx));

    CHECK(is_unfolded_function(RootUnfolded));
    CHECK(is_unfolded_function(MM.M->getFunction("mid.unfolded")));
    CHECK(is_unfolded_function(MM.M->getFunction("leaf.unfolded")));
}

TEST(recursive_fold_chain)
{
    MockModule MM;
    auto *Leaf = MM.makeFolded("fleaf");
    auto *Mid = MM.makeFolded("fmid");
    auto *Root = MM.makeFolded("froot");
    MM.setBodyToCallFn(Mid, Leaf);
    MM.setBodyToCallFn(Root, Mid);

    auto *RootUnfolded = unwrapExpected(unfold_function_state_recursive(Root, MM.BinCtx));
    auto *RootFolded = unwrapExpected(fold_function_state_recursive(RootUnfolded, MM.BinCtx));

    CHECK(is_folded_function(RootFolded));
    CHECK(is_folded_function(MM.M->getFunction("fmid.folded")));
    CHECK(is_folded_function(MM.M->getFunction("fleaf.folded")));
}

TEST(recursive_unfold_rejects_missing_root_attrs)
{
    MockModule MM;
    auto *Root = MM.makeFolded("raw_root", true, false);

    auto Err = takeExpectedError(unfold_function_state_recursive(Root, MM.BinCtx));
    CHECK(Err.find("missing lifted.state_form") != std::string::npos);
}

TEST(recursive_unfold_ignores_unannotated_callees)
{
    MockModule MM;
    auto *Callee = MM.makeFolded("raw_callee", true, false);
    auto *Root = MM.makeFolded("root_with_raw_callee");
    MM.setBodyToCallFn(Root, Callee);

    auto *RootUnfolded = unwrapExpected(unfold_function_state_recursive(Root, MM.BinCtx));
    CHECK(is_unfolded_function(RootUnfolded));
    CHECK(MM.M->getFunction("raw_callee.unfolded") == nullptr);
}

TEST(recursive_unfold_includes_annotated_declaration_callees)
{
    MockModule MM;
    auto *ObserverDecl = MM.makeByvalFolded("observer_decl", false);
    auto *Root = MM.makeFolded("root_calls_observer");
    MM.setBodyToCallFn(Root, ObserverDecl, true);

    auto *RootUnfolded = unwrapExpected(unfold_function_state_recursive(Root, MM.BinCtx));
    auto *ObserverUnfolded = MM.M->getFunction("observer_decl.unfolded");

    CHECK(is_unfolded_function(RootUnfolded));
    CHECK(ObserverUnfolded != nullptr);
    CHECK(is_unfolded_function(ObserverUnfolded));
    CHECK(bodyCallsFunction(RootUnfolded, "observer_decl.unfolded"));
}


TEST(mixed_byval_byptr_recursive)
{
    MockModule MM;
    auto *Leaf = MM.makeByvalFolded("mixed_leaf");
    auto *Root = MM.makeFolded("mixed_root");
    MM.setBodyToCallFn(Root, Leaf, true);

    auto *RootUnfolded = unwrapExpected(unfold_function_state_recursive(Root, MM.BinCtx));
    auto *LeafUnfolded = MM.M->getFunction("mixed_leaf.unfolded");

    CHECK(is_unfolded_function(RootUnfolded));
    CHECK(!is_byval_state(RootUnfolded));
    CHECK(is_unfolded_function(LeafUnfolded));
    CHECK(is_byval_state(LeafUnfolded));
}


TEST(systemv_flags_are_volatile)
{
    auto Volatile = SystemVx64CC::get().getVolatileRegisters();
    bool Found = false;
    for (auto Reg : Volatile)
        if (Reg == ABIRegister::RFLAGS)
            Found = true;
    CHECK(Found);
}

TEST(all_registers_cc_unfold_contract_includes_rip)
{
    MockModule MM("all_regs_unfold");
    const auto &CC = AllRegistersCC::get();
    MM.declareRegisterHelpers(CC.getUnfoldRegisters());

    bool UnfoldHasRip = false;
    for (auto Reg : CC.getUnfoldRegisters())
        if (Reg == ABIRegister::RIP)
            UnfoldHasRip = true;
    CHECK(UnfoldHasRip);

    bool VolatileHasRip = false;
    for (auto Reg : CC.getVolatileRegisters())
        if (Reg == ABIRegister::RIP)
            VolatileHasRip = true;
    CHECK(!VolatileHasRip);

    bool ReturnHasRip = false;
    for (auto Reg : CC.getReturnRegisters())
        if (Reg == ABIRegister::RIP)
            ReturnHasRip = true;
    CHECK(!ReturnHasRip);

    bool CompareHasRip = false;
    for (auto Reg : CC.get_comparison_registers())
        if (Reg == ABIRegister::RIP)
            CompareHasRip = true;
    CHECK(!CompareHasRip);

    auto *U = unwrapExpected(unfold_function_state(MM.makeFolded("all_regs_fold"), CC));
    CHECK_EQ(U->arg_size(), CC.getUnfoldRegisters().size() + 2u);

    auto RipIdx = CC.getUnfoldParamIndex(ABIRegister::RIP);
    CHECK(RipIdx.has_value());
    auto *RipArg = getRegisterArgument(U, CC, ABIRegister::RIP);
    CHECK(RipArg != nullptr);
    CHECK(RipArg == U->getArg(*RipIdx));
    CHECK(RipArg->getType() == MM.PtrTy);
    CHECK(RipArg->getName() == "rip");

    auto *Folded = unwrapExpected(fold_function_state(U, CC));
    CHECK(is_folded_function(Folded));
    CHECK_EQ(Folded->arg_size(), 3u);
}

TEST(all_registers_cc_includes_flags)
{
    const auto &CC = AllRegistersCC::get();
    CHECK(CC.getABIName() == "all_regs");

    bool VolatileHasFlags = false;
    for (auto Reg : CC.getVolatileRegisters())
        if (Reg == ABIRegister::RFLAGS)
            VolatileHasFlags = true;
    CHECK(VolatileHasFlags);

    bool CompareHasFlags = false;
    for (auto Reg : CC.get_comparison_registers())
        if (Reg == ABIRegister::RFLAGS)
            CompareHasFlags = true;
    CHECK(CompareHasFlags);
}