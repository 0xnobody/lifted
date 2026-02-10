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

    llvm::SmallVector<llvm::Value *, 8> EmitArgExtraction(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Value *State,
        llvm::Value *Memory,
        llvm::FunctionType *CalleeTy)
    {
        llvm::Module *M = Builder.GetInsertBlock()->getModule();
        llvm::LLVMContext &Ctx = Builder.getContext();
        llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Ctx);

        auto ArgRegs = CC.getArgRegisters();
        unsigned NumParams = CalleeTy->getNumParams();
        unsigned NumRegArgs = std::min(static_cast<unsigned>(ArgRegs.size()), NumParams);

        llvm::SmallVector<llvm::Value *, 8> Args;

        // Register arguments
        for (unsigned i = 0; i < NumRegArgs; ++i)
        {
            llvm::Value *RegVal = ExtractRegister(Builder, ArgRegs[i], State);
            Args.push_back(CastToType(Builder, RegVal, CalleeTy->getParamType(i)));
        }

        // Stack arguments
        if (NumParams > NumRegArgs)
        {
            unsigned BaseOffset = CC.getStackArgBaseOffset();
            auto &DL = M->getDataLayout();
            unsigned PtrBytes = DL.getPointerSize(0);

            llvm::Value *RSP = ExtractRegister(Builder, ABIRegister::RSP, State);
            llvm::Function *ReadMem64 = M->getFunction("__remill_read_memory_64");
            assert(ReadMem64 && "Missing __remill_read_memory_64");

            for (unsigned i = NumRegArgs; i < NumParams; ++i)
            {
                unsigned SlotIndex = i - NumRegArgs;
                llvm::Value *Offset = llvm::ConstantInt::get(Int64Ty, BaseOffset + SlotIndex * PtrBytes);
                llvm::Value *Addr = Builder.CreateAdd(RSP, Offset);
                llvm::Value *StackVal = Builder.CreateCall(ReadMem64, {Memory, Addr});
                Args.push_back(CastToType(Builder, StackVal, CalleeTy->getParamType(i)));
            }
        }

        return Args;
    }

    void EmitReturnWriteback(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Value *State,
        llvm::Value *RetVal)
    {
        if (!RetVal || RetVal->getType()->isVoidTy())
            return;

        auto RetRegs = CC.getReturnRegisters();

        if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(RetVal->getType()))
        {
            // Multi-register return: {i64, i64} → RAX, RDX
            unsigned NumElements = std::min(StructTy->getNumElements(),
                                            static_cast<unsigned>(RetRegs.size()));
            for (unsigned i = 0; i < NumElements; ++i)
            {
                llvm::Value *Element = Builder.CreateExtractValue(RetVal, i);
                StoreRegister(Builder, RetRegs[i], State, Element);
            }
        }
        else
        {
            // Single-register return → RAX
            StoreRegister(Builder, RetRegs[0], State, RetVal);
        }
    }

    void EmitVolatileClobber(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Value *State,
        unsigned NumReturnRegs)
    {
        llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Builder.getContext());

        auto VolatileRegs = CC.getVolatileRegisters();
        auto ReturnRegs = CC.getReturnRegisters();

        // Build the set of registers that have already been written with return values.
        llvm::SmallDenseSet<ABIRegister, 4> ReturnRegSet;
        for (unsigned i = 0; i < NumReturnRegs && i < ReturnRegs.size(); ++i)
        {
            ReturnRegSet.insert(ReturnRegs[i]);
        }

        // Clobber all volatile registers that are NOT return registers.
        // Use freeze(poison) — produces an arbitrary but fixed value.
        llvm::Value *Clobbered = Builder.CreateFreeze(llvm::PoisonValue::get(Int64Ty));
        for (ABIRegister Reg : VolatileRegs)
        {
            if (!ReturnRegSet.contains(Reg))
            {
                StoreRegister(Builder, Reg, State, Clobbered);
            }
        }
    }

    void EmitRetAddrPop(
        llvm::IRBuilder<> &Builder,
        llvm::Value *State,
        llvm::Value *Memory)
    {
        llvm::Module *M = Builder.GetInsertBlock()->getModule();
        llvm::Type *Int64Ty = llvm::Type::getInt64Ty(Builder.getContext());

        // RIP = [RSP] (pop return address)
        llvm::Value *RSP = ExtractRegister(Builder, ABIRegister::RSP, State);
        llvm::Function *ReadMem64 = M->getFunction("__remill_read_memory_64");
        assert(ReadMem64 && "Missing __remill_read_memory_64");
        llvm::Value *RetAddr = Builder.CreateCall(ReadMem64, {Memory, RSP});

        // Store return address into RIP.
        // RIP doesn't have an ABIRegister entry since it's not a general-purpose register —
        // we use the remill PC register helpers directly.
        llvm::Function *StoreRip = M->getFunction("__store_rip");
        if (StoreRip)
        {
            Builder.CreateCall(StoreRip, {State, RetAddr});
        }
        else
        {
            // Fallback: write to PC through the extract_rip pattern.
            // Caller is responsible for RIP update if __store_rip isn't available.
        }

        // RSP += 8
        llvm::Value *NewRSP = Builder.CreateAdd(RSP, llvm::ConstantInt::get(Int64Ty, 8));
        StoreRegister(Builder, ABIRegister::RSP, State, NewRSP);
    }

    void EmitCall(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Function *Callee,
        llvm::Value *State,
        llvm::Value *Memory)
    {
        // 1. Extract arguments
        auto Args = EmitArgExtraction(Builder, CC, State, Memory, Callee->getFunctionType());

        // 2. Call the target function
        llvm::Value *RetVal = Builder.CreateCall(Callee, Args);

        // 3. Write back return values
        EmitReturnWriteback(Builder, CC, State, RetVal);

        // 4. Clobber volatile registers (except those used for return)
        unsigned NumRetRegs = CC.getNumReturnRegisters(Callee->getReturnType());
        EmitVolatileClobber(Builder, CC, State, NumRetRegs);

        // 5. Pop return address and adjust stack
        EmitRetAddrPop(Builder, State, Memory);
    }

} // namespace lifted::abi
