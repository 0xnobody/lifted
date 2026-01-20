#include <cstdlib>
#include <memory>
#include <string>
#include <iostream>
#include <filesystem>

#include <remill/Arch/Arch.h>

#include "trace-manager.hpp"
#include "lifter.hpp"
#include "verify.hpp"
#include "helpers.hpp"
#include "utils.hpp"
#include "opt.hpp"

#include "passes/redefine_external_calls_pass.hpp"

#include "passes/deobfuscation/canonicalize_stack_pass.hpp"
#include "passes/deobfuscation/width_normalize_pass.hpp"

#include "passes/verification/memory_intrinsic_lowering_pass.hpp"

#include "passes/analysis/stack_aa_pass.hpp"

#include "slicer.hpp"

#include "lifter2.hpp"

using namespace lifted;

llvm::Expected<lifter::LiftingResult> lift_function(const remill::Arch &arch, std::filesystem::path path, const llvm::Module *defs_module)
{
    auto binary = LIEF::Parser::parse(path);
    if (!binary)
    {
        return llvm::make_error<llvm::StringError>("Failed to parse binary: " + path.string(),
                                                   llvm::inconvertibleErrorCode());
    }

    auto rva = lifter::rva_from_export(*binary, "test");
    if (!rva)
    {
        return rva.takeError();
    }

    auto lift_module = remill::LoadArchSemantics(&arch);

    std::set<llvm::AddressRange> const_rva_ranges;
    const_rva_ranges.insert(llvm::AddressRange{0x4030, 0x4080});
    Lifter lifter(&arch,
                  binary.get(),
                  lift_module.get(),
                  const_rva_ranges);

    lifter.Lift(*rva);

    return lifter::lift_function(arch, *binary, *rva, defs_module);
}

llvm::Error run_pipeline(const remill::Arch &arch, std::filesystem::path path, const llvm::Module *defs_module)
{
    std::filesystem::path output_path = path;
    output_path.remove_filename();
    output_path /= path.filename().replace_extension("").string() + "_out";
    std::filesystem::create_directories(output_path);

    // BINARY_FUNC -> [LIFTER] -> LIFTED_IR
    auto lifting_result = lift_function(arch, path, defs_module);
    if (!lifting_result)
    {
        return lifting_result.takeError();
    }

    auto lifted_ir = std::move(lifting_result->module);
    utils::output_to_file(output_path / "lifted_ir.ll", lifted_ir.get());

    // Redefine external calls here
    if (lifting_result->externals_for_redefinition.size() > 0)
    {
        if (auto err = helpers::link_state_utils(lifted_ir.get()); err)
        {
            return err;
        }

        opt::run_pass<RedefineExternalCallsPass, const llvm::Module &, const std::set<llvm::Function *> &>(*lifting_result->lifted_function, *defs_module, lifting_result->externals_for_redefinition);
        utils::output_to_file(output_path / "lifted_ir_redefined.ll", lifted_ir.get());
    }

    // LIFTED_IR + VERIFICATION_INTRINSICS -> [LINKER] -> ORIG_VERIF_IR
    //
    auto orig_verif_ir = llvm::CloneModule(*lifted_ir.get());
    if (auto err = helpers::link_verification_intrinsics(orig_verif_ir.get()); err)
    {
        return err;
    }
    opt::always_inline(orig_verif_ir.get());
    orig_verif_ir->getFunction("__remill_function")->eraseFromParent();
    auto src_fn = orig_verif_ir->getFunction("__unfold_function_systemv_x64_abi");
    src_fn->setName("__src_fn");
    utils::output_to_file(output_path / "orig_verif_ir.ll", orig_verif_ir.get());

    // LIFTED_IR + DEOBFUSCATION_INTRINSICS -> [LINKER] -> DEOB_LINKED_IR
    //
    auto deob_linked_ir = std::move(lifted_ir);
    if (auto err = helpers::link_deobfuscation_intrinsics(deob_linked_ir.get()); err)
    {
        return err;
    }
    opt::always_inline(deob_linked_ir.get());
    deob_linked_ir->getFunction("__remill_function")->eraseFromParent();
    utils::output_to_file(output_path / "deob_linked_ir.ll", deob_linked_ir.get());

    // DEOB_LINKED_IR -> [DEOBFUSCATOR] -> DEOB_IR
    //
    auto deob_ir = std::move(deob_linked_ir);
    auto tgt_fn = deob_ir->getFunction("__unfold_function_systemv_x64_abi");
    tgt_fn->setName("__tgt_fn");
    opt::default_opt(deob_ir.get(), llvm::OptimizationLevel::O1);
    // opt::run_pass<WidthNormalizePass>(*tgt_fn);
    // utils::output_to_file(output_path / "deob_ir.1.ll", deob_ir.get());
    // opt::run_pass<CanonicalizeStackPass>(*tgt_fn);
    // opt::default_opt(deob_ir.get(), llvm::OptimizationLevel::O2);
    utils::output_to_file(output_path / "deob_ir.ll", deob_ir.get());
    tgt_fn = deob_ir->getFunction("__tgt_fn");

    // DEOB_IR -> [VERIFICATION_INSTRUMENTER] -> DEOB_VERIF_IR
    //
    auto deob_verif_ir = std::move(deob_ir);
    opt::run_pass<MemoryIntrinsicLoweringPass>(*tgt_fn);
    utils::output_to_file(output_path / "deob_verif_ir.ll", deob_verif_ir.get());

    // DEOB_VERIF_IR + ORIG_VERIF_IR + VERIF_HARNESS -> [LINKER] -> FINAL_VERIF_IR
    //
    auto deob_verif_ir_extracted = std::make_unique<llvm::Module>("deob_verif_ir_extracted", tgt_fn->getContext());
    remill::MoveFunctionIntoModule(tgt_fn, deob_verif_ir_extracted.get());
    auto final_verif_ir = helpers::link_verification_harness(std::move(orig_verif_ir), std::move(deob_verif_ir_extracted));
    if (!final_verif_ir)
    {
        return final_verif_ir.takeError();
    }
    utils::output_to_file(output_path / "final_verif_ir.ll", final_verif_ir->get());

    return llvm::Error::success();
}

llvm::Error test_klee(llvm::LLVMContext &context)
{
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);

    std::filesystem::path path = EVAL_SYNTHETIC_LIBS_DIR;
    path /= "libeval-branch-polaris.so";
    // path /= "libeval-loop-unbounded-polaris.so";
    // path /= "libeval-test-polaris.so";

    std::filesystem::path output_path = path;
    output_path.remove_filename();
    output_path /= path.filename().replace_extension("").string() + "_out";
    std::filesystem::create_directories(output_path);

    // BINARY_FUNC -> [LIFTER] -> LIFTED_IR
    auto lifting_result = lift_function(*arch, path, nullptr);
    if (!lifting_result)
    {
        return lifting_result.takeError();
    }

    helpers::link_deobfuscation_intrinsics(lifting_result->module.get());
    helpers::link_symbolic_helpers(lifting_result->module.get());
    opt::always_inline(lifting_result->module.get());
    opt::default_opt(lifting_result->module.get(), llvm::OptimizationLevel::O1);
    utils::output_to_file(output_path / "path_condition.ll", lifting_result->module.get());

    auto extract_rip_fn = lifting_result->module->getFunction("__extract_rip");
    auto rip_ptr = extract_rip_fn->getArg(6)->users().begin();

    LiftedCodeAAResult stack_aa(extract_rip_fn->getParent()->getDataLayout());

    auto slice = slicer::computeBackwardSlice(*rip_ptr, *extract_rip_fn, stack_aa);
    // for (auto *inst : slice)
    //{
    //     llvm::outs() << *inst << "\n";
    // }

    return llvm::Error::success();
}

int main(int argc, char **argv)
{
    llvm::LLVMContext context;
    if (auto err = test_klee(context))
    {
        std::cerr << "Error: " << llvm::toString(std::move(err)) << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;

    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);

    std::filesystem::path defs_path = EVAL_SYNTHETIC_LIBS_DIR;
    defs_path /= "defs.ll";

    auto defs_module_or_err = utils::load_module_from_file(defs_path, context);
    if (!defs_module_or_err)
    {
        std::cerr << "Error loading defs module: " << llvm::toString(defs_module_or_err.takeError()) << "\n";
        return EXIT_FAILURE;
    }

    std::filesystem::path binary_path = EVAL_SYNTHETIC_LIBS_DIR;
    // binary_path /= "libeval-test-polaris.so";
    binary_path /= "libeval-branch-polaris.so";

    auto err = run_pipeline(*arch, binary_path, (*defs_module_or_err).get());
    if (err)
    {
        std::cerr << "Error: " << llvm::toString(std::move(err)) << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}