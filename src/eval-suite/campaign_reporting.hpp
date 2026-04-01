#pragma once

#include <filesystem>
#include <iosfwd>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "eval_pipeline.hpp"

namespace lifted::eval
{
struct CsvRow
{
    std::string binary;
    std::string func;
    std::string obfuscator;
    size_t bbs_total = 0;
    std::string stage1_result; // PASS, FAIL, ERROR, LIFT_FAIL
    double stage1_coverage_pct = 0.0;
    std::string stage2_result; // PASS, FAIL, ERROR, N/A
    double stage2_coverage_pct = 0.0;
};


struct StageStats
{
    size_t tested = 0;
    size_t pass = 0;
    size_t fail = 0;
    size_t errors = 0;
    // Coverage is accumulated only for PASS functions; divide by pass_cov_count for the mean.
    double total_coverage_pct = 0.0;
    size_t pass_cov_count = 0;
    // Executor wall-clock time summed across all tested functions (nanoseconds -> ms conversion
    // happens at accumulation; src = JIT side, tgt = Unicorn/comparison side).
    double total_src_wall_ms = 0.0;
    double total_tgt_wall_ms = 0.0;
    std::vector<std::string> failing;
};

struct RunSummary
{
    StageStats stage1;
    StageStats stage2;
    std::vector<std::string> lift_errors;
    std::vector<CsvRow> csv_rows;
    // Lift wall-clock time summed across all successfully-lifted functions.
    double total_lift_ms = 0.0;
    size_t lift_count = 0;

    void record(const std::string &label,
                const FullPipelineResult &r,
                std::string_view binary = "",
                std::string_view func = "",
                std::string_view obfusc = "");

    void record_fatal(const std::string &label,
                      std::string_view binary = "",
                      std::string_view func = "",
                      std::string_view obfusc = "");

    int exit_code() const;
    void print_summary(const std::string &suite_label, std::ostream &os) const;
    void write_csv(const std::filesystem::path &path) const;
};


void write_summary_artifacts(const RunSummary &summary,
                             const std::string &suite_label,
                             const std::filesystem::path &out_dir);

void write_function_dot(const FullPipelineResult &r,
                        const std::filesystem::path &out_dir,
                        const std::string &stem,
                        const std::string &func,
                        const std::string &render_fmt);

void write_function_reports(const FullPipelineResult &r,
                            const std::filesystem::path &out_dir,
                            const std::string &stem,
                            const std::string &func);

struct EvaluatedFunction
{
    std::string suite;
    std::string binary;
    std::string func;
    std::string obfuscator;
    EvaluationRecord record;
};

void write_function_dot(const EvaluatedFunction &result,
                        const std::filesystem::path &out_dir,
                        const std::string &render_fmt);

void write_function_reports(const EvaluatedFunction &result,
                            const std::filesystem::path &out_dir);

void write_campaign_artifacts(const std::string &campaign_label,
                              const std::vector<EvaluatedFunction> &results,
                              const std::filesystem::path &out_dir);


} // namespace lifted::eval
