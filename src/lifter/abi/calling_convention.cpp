#include "calling_convention.hpp"

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>

namespace lifted::abi
{

    unsigned CallingConvention::getNumReturnRegisters(llvm::Type *RetTy) const
    {
        if (RetTy->isVoidTy())
            return 0;

        // Struct returns like {i64, i64} use two registers.
        if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(RetTy))
        {
            unsigned NumElements = StructTy->getNumElements();
            unsigned MaxRegs = getReturnRegisters().size();
            return std::min(NumElements, MaxRegs);
        }

        // Scalar returns use one register.
        return 1;
    }

} // namespace lifted::abi
