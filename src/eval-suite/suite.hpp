#pragma once

#include <string>
#include <filesystem>
#include <vector>

namespace lifted::eval
{

    struct TargetEntry
    {
        std::string func_name;
        uint64_t addr;
    };

    struct SuiteEntry
    {
        std::filesystem::path so_path;
        std::filesystem::path targets_csv_path;
    };

    std::vector<TargetEntry> parse_targets_csv(const std::filesystem::path &csv_path);
    std::vector<SuiteEntry> parse_suite_csv(const std::filesystem::path &csv_path);

}
