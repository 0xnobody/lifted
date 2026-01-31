#pragma once

#include <memory>
#include <llvm/IR/Module.h>

void test(std::unique_ptr<llvm::Module> module);