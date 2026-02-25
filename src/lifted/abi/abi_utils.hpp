#pragma once

#include "calling_convention.hpp"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/ADT/SmallVector.h>

namespace lifted::abi
{

    /// Read a register value from State* using the __extract_<reg> helper.
    llvm::Value *ExtractRegister(llvm::IRBuilder<> &Builder, ABIRegister Reg, llvm::Value *State);

    /// Write a value to a register in State* using the __store_<reg> helper.
    void StoreRegister(llvm::IRBuilder<> &Builder, ABIRegister Reg, llvm::Value *State, llvm::Value *Val);

    /// Cast a value (typically i64 from a register) to the target type.
    /// Handles inttoptr, zext, trunc, bitcast as needed.
    llvm::Value *CastToType(llvm::IRBuilder<> &Builder, llvm::Value *Src, llvm::Type *DstTy);

    /// Cast a value from a user type back to i64 for storing into a register.
    /// Handles ptrtoint, zext, trunc as needed.
    llvm::Value *CastToRegType(llvm::IRBuilder<> &Builder, llvm::Value *Src);

    /// Extract function arguments from State* + Memory according to the calling convention.
    ///
    /// For the first N args (where N = CC.getArgRegisters().size()), reads from ABI registers.
    /// Additional args are read from the stack via __remill_read_memory_64.
    ///
    /// Returns args matching the parameter types of CalleeTy.
    llvm::SmallVector<llvm::Value *, 8> EmitArgExtraction(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Value *State,
        llvm::Value *Memory,
        llvm::FunctionType *CalleeTy);

    /// Write return value(s) back to State* according to the calling convention.
    ///
    /// For scalar returns: stores to the first return register (typically RAX).
    /// For {i64, i64} struct returns: stores element 0 to first return reg (RAX),
    ///   element 1 to second return reg (RDX).
    void EmitReturnWriteback(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Value *State,
        llvm::Value *RetVal);

    /// Write freeze(poison) to all volatile registers, except those used as return
    /// registers for this specific function.
    ///
    /// This models the fact that caller-saved registers hold arbitrary-but-fixed
    /// values after a function call. Using freeze(poison) avoids the non-determinism
    /// problems of undef while still communicating "unknown value" to LLVM.
    ///
    /// @param NumReturnRegs Number of return registers actually used by the function
    ///        (from CC.getNumReturnRegisters()). These are skipped since they've
    ///        already been written with actual return values.
    void EmitVolatileClobber(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Value *State,
        unsigned NumReturnRegs);

    /// Pop the return address from the stack and adjust RSP.
    /// Equivalent to: RIP = [RSP]; RSP += 8.
    void EmitRetAddrPop(
        llvm::IRBuilder<> &Builder,
        llvm::Value *State,
        llvm::Value *Memory);

    /// Emit a complete external function call using the given calling convention.
    ///
    /// 1. Extract arguments from registers/stack
    /// 2. Call the target function
    /// 3. Write back return values
    /// 4. Clobber volatile registers with freeze(poison)
    /// 5. Pop return address and adjust stack
    ///
    /// This is the high-level entry point used by CreateRemoteCallSyntheticBB.
    void EmitCall(
        llvm::IRBuilder<> &Builder,
        const CallingConvention &CC,
        llvm::Function *Callee,
        llvm::Value *State,
        llvm::Value *Memory);

} // namespace lifted::abi
