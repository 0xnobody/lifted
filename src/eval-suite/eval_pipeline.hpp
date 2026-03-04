#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/Error.h>

#include "pipeline/pipeline.hpp"
#include "pipeline/deep_dive.hpp"

namespace lifted::eval
{

// Result of a single lift+verify run.
struct LiftAndVerifyResult
{
    std::optional<pipeline::PipelineReport> report;    // null only if lifting failed
    std::optional<pipeline::DeepDiveResult> deep_dive; // null if no divergence or skipped
    bool lift_failed = false;
    std::string lift_error;                            // populated when lift_failed
};

// Core: lift binary at entry_rva, run the default two-stage pipeline.
// deep_dive_count: 0 = skip deep-dive; >= 1 = deep-dive the first divergence found.
llvm::Expected<LiftAndVerifyResult>
lift_and_verify_named(llvm::LLVMContext &context,
                      const std::filesystem::path &path,
                      const std::string &func_name,
                      uint64_t entry_rva,
                      size_t deep_dive_count = 1);

// Suite name -> compile-time CSV path.  Returns nullopt when the name is
// unknown (i.e. no compile definition was injected for it).
std::optional<std::filesystem::path> resolve_suite_name(const std::string &name);

// List all baked-in suite names (only those whose CSV macros were injected at
// compile time).
std::vector<std::string> known_suite_names();

} // namespace lifted::eval
