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

llvm::Error lift_function(const remill::Arch &arch, std::filesystem::path path, const llvm::Module *defs_module)
{
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

    auto lift_module = remill::LoadArchSemantics(&arch);

    lifted::abi::SystemVx64CC CC;

    std::set<llvm::AddressRange> const_rva_ranges;
    const_rva_ranges.insert(llvm::AddressRange{0x4030, 0x4080});

    std::set<llvm::AddressRange> got_table_rva_ranges;
    got_table_rva_ranges.insert(llvm::AddressRange{0x4000, 0x4020});
    Lifter lifter(&arch,
                  binary.get(),
                  lift_module.get(),
                  const_rva_ranges,
                  got_table_rva_ranges,
                  nullptr,
                  &CC);

    auto lifted = lifter.Lift(*rva);

    if (lifted)
    {
        auto &[M, entry_fn] = *lifted;

        utils::output_to_file("/home/atlas/lifted/out/lifted.ll", M.get());

        auto exec = verification::JITExecutor::create(std::move(M), entry_fn->getName().str());

        if (!exec)
        {
            return exec.takeError();
        }

        verification::verifier_state state(0x1337, binary, *rva);
        auto result = (*exec)->run_single(state);

        std::set<uint64_t> ext_calls_set;
        for (const auto &ext_call : state.external_calls())
        {
            ext_calls_set.insert(ext_call);
        }

        auto emu = verification::UnicornExecutor::create(binary, ext_calls_set, *rva);

        verification::verifier_state emu_state(0x1337, binary, *rva);
        auto emu_result = (*emu)->run_single(emu_state);

        auto cmp_abi = lifted::abi::AllRegistersCC{};
        auto cmp_config = verification::ComparisonConfig::default_config(&cmp_abi);
        auto cmp_result = verification::compare_states(state, emu_state, cmp_config);
        cmp_result.print(std::cout);
    }
}

int main(int argc, char **argv)
{
    llvm::LLVMContext context;
    auto arch = remill::Arch::Get(context, remill::OSName::kOSLinux, remill::ArchName::kArchAMD64);

    std::filesystem::path path = EVAL_SYNTHETIC_LIBS_DIR;
    // path /= "libeval-branch-polaris.so";
    path /= "libeval-ext-call.so";
    // path /= "libeval-test-polaris.so";
    // path /= "libeval-loop-unbounded.so"; // test block splitting

    std::filesystem::path output_path = path;
    output_path.remove_filename();
    output_path /= path.filename().replace_extension("").string() + "_out";
    std::filesystem::create_directories(output_path);

    // BINARY_FUNC -> [LIFTER] -> LIFTED_IR
    auto r = lift_function(*arch, path, nullptr);

    if (r)
    {
        llvm::errs() << "Lifting failed: " << llvm::toString(std::move(r)) << "\n";
    }

    return EXIT_SUCCESS;
}