#include "abi_utils.hpp"

#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>

namespace lifted::abi
{

llvm::Value *ExtractRegister(llvm::IRBuilder<> &Builder, ABIRegister Reg, llvm::Value *State)
{
    llvm::Module *M = Builder.GetInsertBlock()->getModule();
    llvm::StringRef HelperName = getExtractHelperName(Reg);
    llvm::Function *Helper = M->getFunction(HelperName);
    assert(Helper && "Missing __extract_<reg> helper — is state-utils linked?");
    return Builder.CreateCall(Helper, {State});
}

void StoreRegister(llvm::IRBuilder<> &Builder, ABIRegister Reg, llvm::Value *State, llvm::Value *Val)
{
    llvm::Module *M = Builder.GetInsertBlock()->getModule();
    llvm::StringRef HelperName = getStoreHelperName(Reg);
    llvm::Function *Helper = M->getFunction(HelperName);
    assert(Helper && "Missing __store_<reg> helper — is state-utils linked?");

    // Ensure Val is i64 before storing.
    llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Builder.getContext());
    if (Val->getType() != Int64Ty)
    {
        Val = CastToRegType(Builder, Val);
    }

    Builder.CreateCall(Helper, {State, Val});
}

llvm::Value *CastToType(llvm::IRBuilder<> &Builder, llvm::Value *Src, llvm::Type *DstTy)
{
    if (Src->getType() == DstTy)
        return Src;

    auto &DL = Builder.GetInsertBlock()->getModule()->getDataLayout();
    unsigned PtrSize = DL.getPointerSizeInBits();

    unsigned SrcSize = Src->getType()->getScalarSizeInBits();
    unsigned DstSize = DstTy->isPointerTy() ? PtrSize : DstTy->getScalarSizeInBits();

    if (DstTy->isPointerTy())
    {
        // i64 → ptr
        return Builder.CreateIntToPtr(Src, DstTy);
    }

    if (Src->getType()->isPointerTy())
    {
        // ptr → integer
        llvm::Value *AsInt = Builder.CreatePtrToInt(Src, llvm::Type::getInt64Ty(Builder.getContext()));
        if (DstSize == 64)
            return AsInt;
        if (DstSize < 64)
            return Builder.CreateTrunc(AsInt, DstTy);
        return Builder.CreateZExt(AsInt, DstTy);
    }

    if (SrcSize == DstSize)
    {
        return Builder.CreateBitOrPointerCast(Src, DstTy);
    }
    else if (DstTy->isIntegerTy())
    {
        if (SrcSize < DstSize)
            return Builder.CreateZExt(Src, DstTy);
        else
            return Builder.CreateTrunc(Src, DstTy);
    }

    llvm_unreachable("Unsupported cast in ABI utilities");
}

llvm::Value *CastToRegType(llvm::IRBuilder<> &Builder, llvm::Value *Src)
{
    llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Builder.getContext());

    if (Src->getType() == Int64Ty)
        return Src;

    if (Src->getType()->isPointerTy())
    {
        return Builder.CreatePtrToInt(Src, Int64Ty);
    }

    unsigned SrcSize = Src->getType()->getScalarSizeInBits();
    if (SrcSize < 64)
        return Builder.CreateZExt(Src, Int64Ty);
    if (SrcSize > 64)
        return Builder.CreateTrunc(Src, Int64Ty);

    return Builder.CreateBitCast(Src, Int64Ty);
}

} // namespace lifted::abi
