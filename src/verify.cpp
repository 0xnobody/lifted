
#include "verify.hpp"

#include <llvm/IR/Module.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/IRBuilder.h>
#include <klee/Core/Interpreter.h>

#include <vector>

class TestHandler final : public klee::InterpreterHandler
{
private:
    std::unique_ptr<llvm::raw_ostream> m_infoFile;
    uint32_t m_PathsCompleted = 0;
    uint32_t m_PathsExplored = 0;

public:
    TestHandler()
    {
        std::error_code ec;
        m_infoFile = std::make_unique<llvm::raw_fd_ostream>("/home/atlas/klee-pg/info.log", ec, llvm::sys::fs::OF_Text);
    }
    virtual ~TestHandler() override {}

    virtual llvm::raw_ostream &getInfoStream() const override { return *m_infoFile.get(); }

    virtual std::string getOutputFilename(const std::string &filename) override { return "/home/atlas/klee-pg/" + filename + ".out"; }
    virtual std::unique_ptr<llvm::raw_fd_ostream> openOutputFile(const std::string &filename) override
    {
        std::error_code ec;
        auto stream = std::make_unique<llvm::raw_fd_ostream>(getOutputFilename(filename), ec, llvm::sys::fs::OF_Text);
        return stream;
    }

    virtual void incPathsCompleted() override { ++m_PathsCompleted; }
    virtual void incPathsExplored(std::uint32_t num = 1) override { m_PathsExplored += num; }

    virtual void processTestCase(const klee::ExecutionState &state,
                                 const char *err,
                                 const char *suffix) override
    {
    }

    static void reset()
    {
        llvm::sys::fs::remove_directories("/home/atlas/klee-pg/");
        llvm::sys::fs::create_directories("/home/atlas/klee-pg/");
    }
};

void test(std::unique_ptr<llvm::Module> module)
{
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::InitializeNativeTargetAsmParser();

    klee::Interpreter::InterpreterOptions interpreter_opts;
    interpreter_opts.MakeConcreteSymbolic = 1;

    klee::Interpreter::ModuleOptions module_opts(
        "/home/atlas/lifted/build/runtime/lib", // LibraryDir
        "main",                                 // EntryPoint
        "64_Release",                           // OptSuffix
        true,                                   // Optimize
        true,                                   // CheckDivZero
        true                                    // CheckOvershift
    );

    TestHandler::reset();

    klee::InterpreterHandler *handler = new TestHandler();

    klee::Interpreter *interpreter = klee::Interpreter::create(
        module->getContext(),
        interpreter_opts,
        handler);

    auto modules = std::vector<std::unique_ptr<llvm::Module>>();
    modules.push_back(std::move(module));

    const llvm::Module *final_module = interpreter->setModule(
        modules,
        module_opts);

    char *args[] = {"bleh", nullptr};
    char *envp[] = {nullptr};
    interpreter->runFunctionAsMain(final_module->getFunction("main"), 1, args, envp);
}

/*
llvm::Function *extract_path_condition(llvm::Function &fn)
{
    auto module = fn.getParent();

    llvm::Type *ret_type = llvm::Type::getInt64Ty(module->getContext());

    llvm::FunctionType *func_type = llvm::FunctionType::get(
        ret_type,
        fn.getFunctionType()->params(),
        fn.getFunctionType()->isVarArg());

    llvm::Function *path_condition_fn = llvm::Function::Create(
        func_type,
        fn.getLinkage(),
        fn.getName() + "_path_condition",
        module);

    path_condition_fn->copyAttributesFrom(&fn);

    llvm::ValueToValueMapTy VMap;
    for (auto oldArg = fn.arg_begin(), newArg = path_condition_fn->arg_begin();
         oldArg != fn.arg_end(); ++oldArg, ++newArg)
    {
        VMap[&*oldArg] = &*newArg;
        newArg->setName(oldArg->getName());
    }

    // Clone the function body
    llvm::SmallVector<llvm::ReturnInst *, 8> returns;
    CloneFunctionInto(path_condition_fn, &fn, VMap,
                      llvm::CloneFunctionChangeType::LocalChangesOnly, returns);

    for (auto ret : returns)
    {
        llvm::IRBuilder<> builder(ret);
        builder.CreateRet(llvm::ConstantInt::get(ret_type, 0));
        ret->eraseFromParent();
    }
}
    */