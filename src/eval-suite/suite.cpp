#include "suite.hpp"

#include <fstream>
#include <llvm/Support/Error.h>

namespace lifted::eval
{

    std::vector<TargetEntry> parse_targets_csv(const std::filesystem::path &csv_path)
    {
        std::vector<TargetEntry> result;
        std::ifstream f(csv_path);
        if (!f.is_open())
        {
            llvm::errs() << "parse_targets_csv: cannot open " << csv_path.string() << "\n";
            return result;
        }
        std::string line;
        bool header = true;
        while (std::getline(f, line))
        {
            // Strip trailing \r (csv.writer may use \r\n on some platforms)
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (header)
            {
                header = false;
                continue;
            }
            if (line.empty())
                continue;
            auto comma = line.find(',');
            if (comma == std::string::npos)
                continue;
            std::string name = line.substr(0, comma);
            std::string addr_str = line.substr(comma + 1);
            try
            {
                result.push_back({name, static_cast<uint64_t>(std::stoull(addr_str, nullptr, 16))});
            }
            catch (...)
            {
            }
        }
        return result;
    }

    std::vector<SuiteEntry> parse_suite_csv(const std::filesystem::path &csv_path)
    {
        std::vector<SuiteEntry> result;
        std::ifstream f(csv_path);
        if (!f.is_open())
        {
            llvm::errs() << "parse_suite_csv: cannot open " << csv_path.string() << "\n";
            return result;
        }
        std::string line;
        bool header = true;
        while (std::getline(f, line))
        {
            // Strip trailing \r (csv.writer may use \r\n on some platforms)
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (header)
            {
                header = false;
                continue;
            }
            if (line.empty())
                continue;
            auto comma1 = line.find(',');
            if (comma1 == std::string::npos)
                continue;
            std::string_view rest = std::string_view{line}.substr(comma1 + 1);
            auto comma2 = rest.find(',');
            std::string csv_path{comma2 == std::string_view::npos ? rest : rest.substr(0, comma2)};
            std::string obfuscator{comma2 == std::string_view::npos ? std::string_view{} : rest.substr(comma2 + 1)};
            result.push_back({line.substr(0, comma1), csv_path, obfuscator});
        }
        return result;
    }
}
