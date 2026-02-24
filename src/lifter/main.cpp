#include <cstdlib>
#include <memory>
#include <string>
#include <iostream>
#include <filesystem>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#ifdef DEBUG
#undef DEBUG
#include <LIEF/LIEF.hpp>
#define DEBUG
#else
#include <LIEF/LIEF.hpp>
#endif

#include "helpers.hpp"
#include "utils.hpp"
#include "opt.hpp"

#include "lifter2.hpp"

#include "abi/systemv_x64.hpp"

#include "verification/jit_executor.hpp"
#include "verification/unicorn_executor.hpp"
#include "verification/comparator.hpp"

using namespace lifted;

llvm::Expected<uint64_t> rva_from_export(const LIEF::Binary &binary, const std::string &export_name)
{
    auto exports = binary.exported_functions();
    for (const auto &exp : exports)
    {
        if (exp.name() == export_name)
        {
            return exp.address() - binary.imagebase();
        }
    }
    return llvm::createStringError(llvm::inconvertibleErrorCode(), "Export not found: " + export_name);
}

std::optional<llvm::AddressRange> get_section_bounds(const LIEF::Binary &binary, std::string name)
{
    auto format = binary.format();
    switch (format)
    {
    case LIEF::EXE_FORMATS::FORMAT_ELF:
    {
        auto *elf = dynamic_cast<const LIEF::ELF::Binary *>(&binary);
        auto *section = elf->get_section(name);
        if (!section)
            return std::nullopt;
        return llvm::AddressRange{section->virtual_address(), section->virtual_address() + section->size()};
    }
    break;
    case LIEF::EXE_FORMATS::FORMAT_PE:
    {
        auto *pe = dynamic_cast<const LIEF::PE::Binary *>(&binary);
        auto *section = pe->get_section(name);
        if (!section)
            return std::nullopt;
        return llvm::AddressRange{section->virtual_address(), section->virtual_address() + section->size()};
    }
    break;
    case LIEF::EXE_FORMATS::FORMAT_MACHO:
    {
        auto *macho = dynamic_cast<const LIEF::MachO::Binary *>(&binary);
        auto *section = macho->get_section(name);
        if (!section)
            return std::nullopt;
        return llvm::AddressRange{section->virtual_address(), section->virtual_address() + section->size()};
    }
    break;
    default:
    {
        throw std::runtime_error("Unsupported LIEF format");
    }
    break;
    }
}

llvm::Error lift_and_verify(llvm::LLVMContext &context, std::filesystem::path path, const llvm::Module *defs_module)
{
    // TODO: figure out how to avoid loading arch/semantics for each lift
    //
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);
    auto lift_module = remill::LoadArchSemantics(arch.get());

    std::shared_ptr<LIEF::Binary> binary = LIEF::Parser::parse(path);
    if (!binary)
    {
        return llvm::make_error<llvm::StringError>("Failed to parse binary: " + path.string(),
                                                   llvm::inconvertibleErrorCode());
    }

    auto rva = rva_from_export(*binary, "test");
    if (!rva)
    {
        return rva.takeError();
    }

    lifted::abi::SystemVx64CC CC;

    std::set<llvm::AddressRange> const_rva_ranges;
    // const_rva_ranges.insert(llvm::AddressRange{0x4030, 0x4080}); // obfuscator dependant

    std::set<llvm::AddressRange> got_table_rva_ranges;
    if (auto got_range = get_section_bounds(*binary, ".got"))
    {
        got_table_rva_ranges.insert(*got_range);
    }

    std::set<llvm::AddressRange> ext_func_rva_ranges;
    if (auto plt_range = get_section_bounds(*binary, ".plt.sec"))
    {
        ext_func_rva_ranges.insert(*plt_range);
    }

    Lifter lifter(arch.get(),
                  binary.get(),
                  lift_module.get(),
                  const_rva_ranges,
                  got_table_rva_ranges,
                  ext_func_rva_ranges,
                  nullptr,
                  &CC);

    auto lift_result = lifter.Lift(*rva, true);

    if (lift_result)
    {
        utils::output_to_file("/home/atlas/lifted/out/lifted.ll", lift_result->Module.get());

        verification::run_params_t run_params =
            {
                .seed = 0x1337,
                .binary = binary,
                .entry_rva = *rva,
                .oracle = nullptr};

        verification::verification_params_t verif_params =
            {
                .checkpoint_config = {
                    .flags = verification::record_on_flags::DEFAULT,
                    .prev_record = nullptr}};

        auto exec = verification::JITExecutor::create(std::move(lift_result->Module), lift_result->LiftedFunction->getName().str());
        if (!exec)
        {
            return exec.takeError();
        }

        auto result = (*exec)->run_single(run_params, verif_params);

        if (!result)
        {
            return result.takeError();
        }

        llvm::outs() << "External calls:\n";
        std::set<uint64_t> ext_calls_set;
        for (const auto &ext_call : result->ext_calls)
        {
            ext_calls_set.insert(ext_call);

            llvm::outs() << "\t0x" << llvm::format_hex(ext_call, 16) << "\n";
        }

        auto emu = verification::UnicornExecutor::create(binary, ext_calls_set, *rva);

        verif_params.checkpoint_config.prev_record = &result->checkpoint_record; // Share checkpoints between JIT and Unicorn for cross-validation
        auto emu_result = (*emu)->run_single(run_params, verif_params);

        if (!emu_result)
        {
            return emu_result.takeError();
        }

        // Compare JIT and Unicorn results.
        auto cmp = verification::compare_runs(*result, *emu_result);
        cmp.print(std::cout);

        if (cmp.status == verification::comparison_status::NEEDS_RERUN)
        {
            verif_params.checkpoint_config.prev_record = &emu_result->checkpoint_record;

            result = (*exec)->run_single(run_params, verif_params);
            if (!result)
            {
                return result.takeError();
            }

            cmp = verification::compare_runs(*result, *emu_result);
            cmp.print(std::cout);
        }

        if (cmp.status == verification::comparison_status::FAIL_DIVERGED)
        {
            auto diff = verification::diff_runs(*result, *emu_result);
            diff.print(std::cout);
        }
    }
}

std::array<std::string, 11> synthetic_test_bins = {
    "libeval-arithmetic",
    "libeval-branch",
    "libeval-ext-call-branching",
    "libeval-ext-call-stack-args",
    "libeval-ext-call",
    //"libeval-indirect-call",
    "libeval-local-vars",
    "libeval-loop-bounded",
    "libeval-loop-unbounded",
    "libeval-stack-args",
    "libeval-stack-loop",
    //"libeval-switch",
    "libeval-test",
};

int main(int argc, char **argv)
{
    llvm::LLVMContext context;

    // std::filesystem::path custom_path = EVAL_SYNTHETIC_LIBS_DIR;
    // custom_path /= "libeval-loop-bounded.so";
    // auto custom_r = lift_and_verify(context, custom_path, nullptr);

    for (auto &test : synthetic_test_bins)
    {
        llvm::outs() << "Running test: " << test << "\n";
        std::filesystem::path path = EVAL_SYNTHETIC_LIBS_DIR;
        path /= test + ".so";

        auto r = lift_and_verify(context, path, nullptr);

        if (r)
        {
            llvm::errs() << "Lifting failed: " << llvm::toString(std::move(r)) << "\n";
        }
    }

    return EXIT_SUCCESS;
}