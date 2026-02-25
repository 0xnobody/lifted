
#include "pass_utils.hpp"

#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/Operator.h>

using namespace llvm;

namespace lifted::passes
{
    llvm::GlobalVariable *getRAM(llvm::Module &module)
    {
        for (GlobalVariable &GV : module.globals())
        {
            if (GV.getName().contains("RAM"))
            {
                return &GV;
            }
        }
        return nullptr;
    }
    llvm::GEPOperator *isRAMGEP(llvm::Value *V)
    {
        if (GEPOperator *GEP = dyn_cast<GEPOperator>(V))
        {
            if (GlobalVariable *GV = dyn_cast<GlobalVariable>(GEP->getPointerOperand()))
            {
                if (GV->getName().contains("RAM"))
                {
                    return GEP;
                }
            }
        }
        return nullptr;
    }

    bool isStackPointer(const Value *V)
    {
        if (V == nullptr)
            return false;

        // Check if this is the rsp parameter or derived from it
        // In remill, rsp is typically a function argument
        if (const Argument *Arg = dyn_cast<Argument>(V))
        {
            return Arg->getName().contains("rsp");
        }
        return false;
    }

    bool isRAMPointer(const Value *V)
    {
        if (V == nullptr)
            return false;

        if (const GlobalVariable *GV = dyn_cast<GlobalVariable>(V))
        {
            return GV->getName().contains("RAM");
        }
        return false;
    }
}