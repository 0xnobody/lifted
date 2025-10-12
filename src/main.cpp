#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>
#include <llvm/IR/LLVMContext.h>
#include <iostream>

int main() {
  llvm::LLVMContext context;
  
  // Get x86-64 architecture
  auto arch = remill::Arch::Get(context, 
                                remill::kArchAMD64,
                                remill::kOSLinux);
  
  std::cout << "Using Remill " << arch->arch_name << std::endl;
  
  return 0;
}