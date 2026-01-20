#pragma once

namespace llvm
{
    class Value;
    class Module;
    class Function;
    class GlobalVariable;
    class GEPOperator;
}

namespace lifted::passes
{
    llvm::GlobalVariable *getRAM(llvm::Module &module);
    llvm::GEPOperator *isRAMGEP(llvm::Value *V);

    bool isStackPointer(const llvm::Value *V);
    bool isRAMPointer(const llvm::Value *V);
}