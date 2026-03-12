#pragma once

#include "calling_convention.hpp"

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>

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

} // namespace lifted::abi
