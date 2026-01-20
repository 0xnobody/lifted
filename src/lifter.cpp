
#include "lifter.hpp"

namespace lifted::lifter
{
    llvm::Expected<uint32_t> rva_from_export(const LIEF::Binary &binary, const std::string &export_name)
    {
        auto exports = binary.exported_functions();
        auto it = std::find_if(exports.begin(), exports.end(), [&](const LIEF::Function &f)
                               {
            auto name = f.name();
            return name == export_name; });

        if (it == exports.end())
        {
            return llvm::make_error<llvm::StringError>(
                "Could not find exported function '" + export_name + "'",
                llvm::inconvertibleErrorCode());
        }

        return it->address() - binary.imagebase();
    }

    std::tuple<std::unique_ptr<llvm::Module>, llvm::Function *> apply_lifting_optimizations(const remill::Arch &arch, SimpleTraceManager &manager, llvm::Module *module, std::set<llvm::Function *> &externals_for_redefinition)
    {
        // Remove llvm.compiler.used to not preserve unused semantics
        auto compilerUsed = module->getGlobalVariable("llvm.compiler.used", true);
        if (compilerUsed != nullptr)
        {
            compilerUsed->eraseFromParent();
        }

        // Remove ISEL_ globals that contain pointers to the semantic functions
        std::vector<llvm::GlobalVariable *> erase;
        for (auto &G : module->globals())
        {
            if (G.getName().startswith("ISEL_"))
            {
                erase.push_back(&G);
            }
        }
        for (auto G : erase)
        {
            G->eraseFromParent();
        }

        // Remove function that keeps the references to unused intrinsics
        auto remillIntrinsics = module->getFunction("__remill_intrinsics");
        if (remillIntrinsics != nullptr)
        {
            remillIntrinsics->eraseFromParent();
        }

        // Remove the implementation of the __remill_sync_hyper_call from the bitcode, because
        // after inlining things get very confusing if this is actually called.
        // TODO: this should probably be removed
        auto hyperCall = module->getFunction("__remill_sync_hyper_call");
        if (hyperCall != nullptr)
        {
            auto name = hyperCall->getName();
            auto ty = hyperCall->getFunctionType();
            auto newFn = module->getOrInsertFunction(name.str() + "_", ty);
            hyperCall->replaceAllUsesWith(newFn.getCallee());
            hyperCall->eraseFromParent();
            newFn.getCallee()->setName(name);
        }

        // A lot of intrinsic functions are (incorrectly) marked as [[gnu::const]].
        // This causes problems where optimizer's assumptions are violated when an
        // implementation is provided. To work around this we remove these attributes
        // from the functions and from the call sites.
        // Another workaround is to first do a separate inline pass and then O3.
        // NOTE: This was fixed in https://github.com/lifting-bits/remill/commit/7f091d42
        for (auto &function : module->functions())
        {
            if (!function.getName().startswith("__remill_"))
            {
                continue;
            }

            function.removeFnAttr(llvm::Attribute::ReadNone);
            for (auto &argument : function.args())
            {
                argument.removeAttr(llvm::Attribute::ReadNone);
            }
            for (auto user : function.users())
            {
                if (auto call = llvm::dyn_cast<llvm::CallInst>(user))
                {
                    call->removeFnAttr(llvm::Attribute::ReadNone);
                }
            }
        }

        // Optimize the module, but with a particular focus on only the functions
        // that we actually lifted.
        remill::OptimizationGuide guide = {};
        remill::OptimizeModule(&arch, module, manager.traces, guide);

        // Create a new module in which we will move all the lifted functions. Prepare
        // the module for code of this architecture, i.e. set the data layout, triple,
        // etc.
        auto dest_module = std::make_unique<llvm::Module>("lifted_code", module->getContext());
        arch.PrepareModuleDataLayout(dest_module.get());

        llvm::Function *entry_trace = nullptr;
        std::set<llvm::Function *> externals_for_redefinition_new;

        // Move the lifted code into a new module. This module will be much smaller
        // because it won't be bogged down with all of the semantics definitions.
        // This is a good JITing strategy: optimize the lifted code in the semantics
        // module, move it to a new module, instrument it there, then JIT compile it.
        for (auto &lifted_entry : manager.traces)
        {
            if (lifted_entry.first == manager.entry)
            {
                entry_trace = lifted_entry.second;
                entry_trace->setName("__remill_function");
                entry_trace->addFnAttr(llvm::Attribute::AlwaysInline);
                entry_trace->addFnAttr(llvm::Attribute::NoUnwind);
            }

            remill::MoveFunctionIntoModule(lifted_entry.second, dest_module.get());
        }

        for (auto &func : externals_for_redefinition)
        {
            if (auto new_func = dest_module->getFunction(func->getName()); new_func != nullptr)
            {
                externals_for_redefinition_new.insert(new_func);
            }
        }
        externals_for_redefinition = std::move(externals_for_redefinition_new);

        return {std::move(dest_module), dest_module->getFunction("__remill_function")};
    }

    llvm::Expected<LiftingResult> lift_function(const remill::Arch &arch, const LIEF::Binary &binary, uint64_t rva, const llvm::Module *defs)
    {
        auto module = remill::LoadArchSemantics(&arch);

        remill::IntrinsicTable intrinsics(module.get());
        auto inst_lifter = arch.DefaultLifter(intrinsics);

        Memory memory;
        auto trace_manager = SimpleTraceManager(&arch, module.get(), memory, &binary, rva, defs);

        remill::TraceLifter trace_lifter(&arch, &trace_manager);
        trace_lifter.Lift(rva);

        if (trace_manager.undefined_externals.size() > 0)
        {
            for (auto *fn : trace_manager.undefined_externals)
            {
                llvm::errs() << "Undefined external: " << fn->getName() << "\n";
            }

            return llvm::make_error<llvm::StringError>(
                "Undefined externals found during lifting",
                llvm::inconvertibleErrorCode());
        }

        llvm::Function *lifted_function = nullptr;
        std::tie(module, lifted_function) = apply_lifting_optimizations(arch, trace_manager, module.get(), trace_manager.defined_externals);

        return LiftingResult{std::move(module), lifted_function, trace_manager.defined_externals};
    }
}