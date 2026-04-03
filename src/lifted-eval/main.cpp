#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/raw_ostream.h>

#include <glog/logging.h>

#include "campaign_reporting.hpp"
#include "eval_pipeline.hpp"
#include "suite.hpp"
#include "utils.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
namespace fs = std::filesystem;
using namespace llvm;
using namespace lifted::eval;
using namespace lifted::fault_injection;

namespace
{
static cl::OptionCategory LiftedEvalCategory("lifted-eval options");

static cl::list<std::string> SuiteOpt(
    "suite",
    cl::desc("Suites to run (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));
static cl::opt<std::string> ObfuscatorOpt(
    "obfuscator",
    cl::desc("Obfuscator filter: none, polaris, or all (default: all)"),
    cl::init("all"),
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> TargetOpt(
    "target",
    cl::desc("Target stems to include (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> FuncOpt(
    "func",
    cl::desc("Function filters as target::func (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> IgnoreOpt(
    "ignore",
    cl::desc("Target stems or target::func labels to skip (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));

static cl::opt<bool> WithStandardOpt(
    "with-standard",
    cl::desc("Force standard evaluation campaigns on"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithoutStandardOpt(
    "without-standard",
    cl::desc("Disable standard evaluation campaigns"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithMutationOpt(
    "with-mutation",
    cl::desc("Force mutation campaigns on"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithoutMutationOpt(
    "without-mutation",
    cl::desc("Disable mutation campaigns"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> WithPolarisMutationOpt(
    "with-polaris-mutation",
    cl::desc("Enable mutation campaigns for Polaris targets"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));

static cl::opt<bool> Eg1Opt(
    "eg1",
    cl::desc("Run EG1 (raw lifted IR vs native binary)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> Eg2Opt(
    "eg2",
    cl::desc("Run EG2 (raw lifted IR vs O2 IR, gated by EG1)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> Eg3Opt(
    "eg3",
    cl::desc("Run EG3 (O2 self-test and mutation gating)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> AllEgsOpt(
    "all-egs",
    cl::desc("Run EG1 + EG2 + EG3 (default when no EG flag is supplied)"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));

static cl::opt<int> MutationBudgetOpt(
    "mutation-budget",
    cl::desc("Mutation budget per function (default: 200)"),
    cl::init(200),
    cl::cat(LiftedEvalCategory));
static cl::opt<std::string> MutationSeedOpt(
    "mutation-seed",
    cl::desc("Mutation RNG seed in hex (default: 0x1337)"),
    cl::init("0x1337"),
    cl::cat(LiftedEvalCategory));
static cl::list<std::string> MutationCategoriesOpt(
    "mutation-categories",
    cl::desc("Mutation category filter (comma-separated)"),
    cl::CommaSeparated,
    cl::cat(LiftedEvalCategory));

static cl::opt<std::string> OutputRootOpt(
    "output-root",
    cl::desc("Root directory for evaluation outputs"),
    cl::init("eval/results"),
    cl::cat(LiftedEvalCategory));
static cl::opt<int> MaxDeepDivesOpt(
    "max-deep-dives",
    cl::desc("Deep-dive divergences per function: 0=skip, 1=first (default)"),
    cl::init(1),
    cl::cat(LiftedEvalCategory));
static cl::opt<std::string> RenderCfgOpt(
    "render-cfg",
    cl::desc("Render CFGs via graphviz (svg|png|pdf)"),
    cl::init(""),
    cl::cat(LiftedEvalCategory));
static cl::opt<int> JobsOpt(
    "jobs",
    cl::desc("Functions to evaluate concurrently per campaign (0=hardware concurrency)"),
    cl::init(0),
    cl::cat(LiftedEvalCategory));
static cl::opt<uint64_t> LiftTimeoutSecOpt(
    "lift-timeout-sec",
    cl::desc("Hard timeout in seconds while waiting for lift completion (0=disabled)"),
    cl::init(0),
    cl::cat(LiftedEvalCategory));
static cl::opt<bool> ListOpt(
    "list",
    cl::desc("Print the planned campaign matrix without executing it"),
    cl::init(false),
    cl::cat(LiftedEvalCategory));

static cl::opt<bool> ChildEvalOpt(
    "child-eval",
    cl::desc("Internal: evaluate exactly one function"),
    cl::init(false),
    cl::Hidden);
static cl::opt<std::string> ChildSoPathOpt(
    "child-so-path",
    cl::desc("Internal: shared object path for child evaluation"),
    cl::init(""),
    cl::Hidden);
static cl::opt<std::string> ChildFuncOpt(
    "child-func",
    cl::desc("Internal: function name for child evaluation"),
    cl::init(""),
    cl::Hidden);
static cl::opt<uint64_t> ChildAddrOpt(
    "child-addr",
    cl::desc("Internal: function RVA for child evaluation"),
    cl::init(0),
    cl::Hidden);
static cl::opt<std::string> ChildResultPathOpt(
    "child-result-path",
    cl::desc("Internal: result JSON path for child evaluation"),
    cl::init(""),
    cl::Hidden);
static cl::opt<int> ChildLiftFdOpt(
    "child-lift-fd",
    cl::desc("Internal: write FD used to signal lift completion"),
    cl::init(-1),
    cl::Hidden);
static cl::opt<uint64_t> ChildDeepDivesOpt(
    "child-deep-dives",
    cl::desc("Internal: deep-dive budget for child evaluation"),
    cl::init(1),
    cl::Hidden);
static cl::opt<std::string> ChildObfuscatorOpt(
    "child-obfuscator",
    cl::desc("Internal: obfuscator for child evaluation"),
    cl::init(""),
    cl::Hidden);
static cl::opt<int> ChildRunRawVsNativeOpt(
    "child-run-raw-vs-native",
    cl::desc("Internal: whether child should run EG1"),
    cl::init(1),
    cl::Hidden);
static cl::opt<int> ChildRunOptVsRawOpt(
    "child-run-opt-vs-raw",
    cl::desc("Internal: whether child should run EG2"),
    cl::init(1),
    cl::Hidden);
static cl::opt<int> ChildRunEg3StrictOpt(
    "child-run-eg3-strict",
    cl::desc("Internal: whether child should run EG3 strict"),
    cl::init(0),
    cl::Hidden);
static cl::opt<int> ChildRunEg3RelaxedOpt(
    "child-run-eg3-relaxed",
    cl::desc("Internal: whether child should run EG3 relaxed"),
    cl::init(0),
    cl::Hidden);
static cl::opt<int> ChildRunMutationOpt(
    "child-run-mutation",
    cl::desc("Internal: whether child should run mutation"),
    cl::init(0),
    cl::Hidden);
static cl::opt<uint64_t> ChildMutationBudgetOpt(
    "child-mutation-budget",
    cl::desc("Internal: mutation budget for child evaluation"),
    cl::init(200),
    cl::Hidden);
static cl::opt<uint64_t> ChildMutationSeedOpt(
    "child-mutation-seed",
    cl::desc("Internal: mutation seed for child evaluation"),
    cl::init(0x1337),
    cl::Hidden);
static cl::list<std::string> ChildMutationCategoryOpt(
    "child-mutation-category",
    cl::desc("Internal: mutation category filter for child evaluation"),
    cl::Hidden);
static cl::opt<uint64_t> ChildLiftTimeoutSecOpt(
    "child-lift-timeout-sec",
    cl::desc("Internal: configured lift timeout for child evaluation"),
    cl::init(0),
    cl::Hidden);

struct CampaignPlan
{
    std::string suite;
    std::string obfuscator; // raw: "" or "polaris"
    bool mutation = false;
    fs::path output_dir;
    EvaluationConfig config;
};

struct FunctionWorkItem
{
    size_t ordinal = 0;
    fs::path so_path;
    std::string binary;
    std::string func;
    uint64_t addr = 0;
};

std::string target_stem(const fs::path &so_path)
{
    std::string stem = so_path.stem().string();
    if (stem.starts_with("libeval-"))
        return stem.substr(8);
    if (stem.starts_with("lib"))
        return stem.substr(3);
    return stem;
}

std::string obfuscator_name(std::string_view obfuscator)
{
    return obfuscator.empty() ? "none" : std::string(obfuscator);
}

std::optional<MutationCategory> parse_category(const std::string &s)
{
    if (s == "arithmetic" || s == "ARITHMETIC")
        return MutationCategory::ARITHMETIC;
    if (s == "bitwise" || s == "BITWISE")
        return MutationCategory::BITWISE;
    if (s == "comparison_neg" || s == "COMPARISON_NEG")
        return MutationCategory::COMPARISON_NEG;
    if (s == "comparison_bdry" || s == "COMPARISON_BDRY")
        return MutationCategory::COMPARISON_BDRY;
    if (s == "operand_swap" || s == "OPERAND_SWAP")
        return MutationCategory::OPERAND_SWAP;
    if (s == "drop_computation" || s == "DROP_COMPUTATION")
        return MutationCategory::DROP_COMPUTATION;
    if (s == "constant_repl" || s == "CONSTANT_REPL")
        return MutationCategory::CONSTANT_REPL;
    if (s == "negate_trunc" || s == "NEGATE_TRUNC")
        return MutationCategory::NEGATE_TRUNC;
    return std::nullopt;
}

constexpr int kChildLiftCheckpointFd = 198;
std::atomic_uint64_t NextChildResultId{0};

llvm::Error make_string_error(const std::string &message)
{
    return llvm::make_error<llvm::StringError>(message, llvm::inconvertibleErrorCode());
}

void close_fd_if_open(int &fd)
{
    if (fd < 0)
        return;
    while (::close(fd) != 0)
    {
        if (errno == EINTR)
            continue;
        break;
    }
    fd = -1;
}

llvm::Error set_close_on_exec(int fd)
{
    const int flags = ::fcntl(fd, F_GETFD);
    if (flags < 0)
        return make_string_error(
            "fcntl(F_GETFD) failed for fd " + std::to_string(fd) + ": " + std::strerror(errno));
    if (::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
        return make_string_error(
            "fcntl(F_SETFD) failed for fd " + std::to_string(fd) + ": " + std::strerror(errno));
    return llvm::Error::success();
}

std::string wait_status_description(int status)
{
    if (WIFEXITED(status))
        return "exit code " + std::to_string(WEXITSTATUS(status));
    if (WIFSIGNALED(status))
        return "signal " + std::to_string(WTERMSIG(status));
    return "unknown wait status";
}

void kill_and_reap(pid_t pid)
{
    if (pid <= 0)
        return;
    if (::kill(pid, SIGKILL) != 0 && errno != ESRCH)
    {
        // Best-effort cleanup: still wait below in case the child already exited.
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0)
    {
        if (errno == EINTR)
            continue;
        if (errno == ECHILD)
            break;
        break;
    }
}

void append_flag_arg(std::vector<std::string> &args, std::string_view flag, const std::string &value)
{
    args.push_back(std::string(flag) + "=" + value);
}

template <typename T>
void append_flag_arg(std::vector<std::string> &args, std::string_view flag, T value)
{
    args.push_back(std::string(flag) + "=" + std::to_string(value));
}

std::string mutation_category_arg(MutationCategory cat)
{
    switch (cat)
    {
    case MutationCategory::ARITHMETIC:
        return "ARITHMETIC";
    case MutationCategory::BITWISE:
        return "BITWISE";
    case MutationCategory::COMPARISON_NEG:
        return "COMPARISON_NEG";
    case MutationCategory::COMPARISON_BDRY:
        return "COMPARISON_BDRY";
    case MutationCategory::OPERAND_SWAP:
        return "OPERAND_SWAP";
    case MutationCategory::DROP_COMPUTATION:
        return "DROP_COMPUTATION";
    case MutationCategory::CONSTANT_REPL:
        return "CONSTANT_REPL";
    case MutationCategory::NEGATE_TRUNC:
        return "NEGATE_TRUNC";
    }
    return "UNKNOWN";
}

llvm::Expected<fs::path> current_executable_path(const char *argv0)
{
    std::error_code ec;
    fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    if (!ec && !exe.empty())
        return exe;

    if (argv0 && *argv0)
    {
        fs::path argv0_path(argv0);
        if (argv0_path.is_absolute() || argv0_path.has_parent_path())
        {
            fs::path absolute_path = fs::absolute(argv0_path, ec);
            if (!ec)
                return absolute_path;
        }

        if (const char *path_env = std::getenv("PATH"))
        {
            std::string_view remaining(path_env);
            while (true)
            {
                const size_t sep = remaining.find(':');
                const std::string_view entry = remaining.substr(0, sep);

                fs::path base;
                if (entry.empty())
                {
                    std::error_code cwd_ec;
                    base = fs::current_path(cwd_ec);
                    if (cwd_ec)
                    {
                        if (sep == std::string_view::npos)
                            break;
                        remaining.remove_prefix(sep + 1);
                        continue;
                    }
                }
                else
                {
                    base = fs::path(entry);
                }

                fs::path candidate = base / argv0;
                if (::access(candidate.c_str(), X_OK) == 0)
                    return candidate;

                if (sep == std::string_view::npos)
                    break;
                remaining.remove_prefix(sep + 1);
            }
        }
    }

    return make_string_error(
        "unable to resolve current executable path for child evaluation spawning");
}

llvm::Expected<fs::path> make_child_result_path()
{
    std::error_code ec;
    const fs::path temp_dir = fs::temp_directory_path(ec);
    if (ec)
        return make_string_error(
            "failed to resolve temporary directory for child result JSON: " + ec.message());

    for (size_t attempt = 0; attempt < 1024; ++attempt)
    {
        const uint64_t unique = NextChildResultId.fetch_add(1);
        fs::path path = temp_dir / (
            "lifted-eval-child-" + std::to_string(::getpid()) + "-" + std::to_string(unique) + ".json");
        ec.clear();
        if (!fs::exists(path, ec))
            return path;
        if (ec)
            return make_string_error(
                "failed to probe temporary child result path '" + path.string() + "': " + ec.message());
    }

    return make_string_error("failed to allocate unique child result path");
}

llvm::Expected<EvaluationConfig> child_config_from_options()
{
    EvaluationConfig cfg;
    cfg.deep_dive_count = static_cast<size_t>(ChildDeepDivesOpt);
    cfg.obfuscator = ChildObfuscatorOpt;
    cfg.run_raw_vs_native = ChildRunRawVsNativeOpt != 0;
    cfg.run_opt_vs_raw = ChildRunOptVsRawOpt != 0;
    cfg.run_eg3_strict = ChildRunEg3StrictOpt != 0;
    cfg.run_eg3_relaxed = ChildRunEg3RelaxedOpt != 0;
    cfg.run_mutation = ChildRunMutationOpt != 0;
    cfg.mutation_config.budget = static_cast<size_t>(ChildMutationBudgetOpt);
    cfg.mutation_config.seed = ChildMutationSeedOpt;
    cfg.lift_timeout_sec = ChildLiftTimeoutSecOpt;

    for (const auto &cat_str : ChildMutationCategoryOpt)
    {
        auto cat = parse_category(cat_str);
        if (!cat)
            return make_string_error(
                "unknown child mutation category '" + cat_str + "'");
        cfg.mutation_config.filter_categories.push_back(*cat);
    }

    return cfg;
}

int run_child_evaluation_mode()
{
    if (ChildSoPathOpt.empty() || ChildFuncOpt.empty() || ChildResultPathOpt.empty() ||
        ChildLiftFdOpt < 0)
    {
        errs() << "lifted-eval child error: missing required child evaluation arguments\n";
        return 2;
    }

    auto config_or = child_config_from_options();
    if (!config_or)
    {
        errs() << "lifted-eval child error: " << toString(config_or.takeError()) << "\n";
        return 2;
    }

    llvm::LLVMContext local_ctx;
    int checkpoint_fd = ChildLiftFdOpt;
    auto on_lift_complete = [&](const EvaluationRecord &) -> llvm::Error {
        const char marker = 'L';
        while (true)
        {
            const ssize_t written = ::write(checkpoint_fd, &marker, 1);
            if (written == 1)
                break;
            if (written < 0 && errno == EINTR)
                continue;
            return make_string_error(
                "failed to write lift completion checkpoint: " + std::string(std::strerror(errno)));
        }
        close_fd_if_open(checkpoint_fd);
        return llvm::Error::success();
    };

    auto record_or = run_evaluation_named(
        local_ctx,
        fs::path(std::string(ChildSoPathOpt)),
        ChildFuncOpt,
        ChildAddrOpt,
        *config_or,
        on_lift_complete);
    close_fd_if_open(checkpoint_fd);
    if (!record_or)
    {
        errs() << "lifted-eval child error: " << toString(record_or.takeError()) << "\n";
        return 2;
    }

    if (auto err = write_evaluation_record_json(
            *record_or, fs::path(std::string(ChildResultPathOpt))))
    {
        errs() << "lifted-eval child error: " << toString(std::move(err)) << "\n";
        return 2;
    }

    return 0;
}

llvm::Expected<EvaluationRecord> read_child_result(const FunctionWorkItem &item,
                                                    const fs::path &result_path,
                                                    int child_status)
{
    auto record_or = read_evaluation_record_json(result_path);
    std::error_code remove_ec;
    fs::remove(result_path, remove_ec);
    if (!record_or)
    {
        return make_string_error(
            "child evaluation for " + item.binary + "::" + item.func +
            " failed to load result JSON '" + result_path.string() +
            "' after " + wait_status_description(child_status) + ": " +
            toString(record_or.takeError()));
    }
    return std::move(*record_or);
}

llvm::Expected<EvaluationRecord> run_evaluation_in_child(const fs::path &exe_path,
                                                          const FunctionWorkItem &item,
                                                          const EvaluationConfig &config)
{
    auto result_path_or = make_child_result_path();
    if (!result_path_or)
        return result_path_or.takeError();
    const fs::path result_path = *result_path_or;

    int checkpoint_pipe[2] = {-1, -1};
    if (::pipe(checkpoint_pipe) != 0)
    {
        return make_string_error(
            "pipe() failed for child evaluation checkpoint: " + std::string(std::strerror(errno)));
    }
    if (auto err = set_close_on_exec(checkpoint_pipe[0]))
    {
        close_fd_if_open(checkpoint_pipe[0]);
        close_fd_if_open(checkpoint_pipe[1]);
        return err;
    }
    if (auto err = set_close_on_exec(checkpoint_pipe[1]))
    {
        close_fd_if_open(checkpoint_pipe[0]);
        close_fd_if_open(checkpoint_pipe[1]);
        return err;
    }

    posix_spawn_file_actions_t file_actions;
    int rc = ::posix_spawn_file_actions_init(&file_actions);
    if (rc != 0)
    {
        close_fd_if_open(checkpoint_pipe[0]);
        close_fd_if_open(checkpoint_pipe[1]);
        return make_string_error(
            "posix_spawn_file_actions_init failed: " + std::string(std::strerror(rc)));
    }

    const auto fail_before_spawn = [&](const std::string &message) -> llvm::Expected<EvaluationRecord> {
        ::posix_spawn_file_actions_destroy(&file_actions);
        close_fd_if_open(checkpoint_pipe[0]);
        close_fd_if_open(checkpoint_pipe[1]);
        return make_string_error(message);
    };

    rc = ::posix_spawn_file_actions_addclose(&file_actions, checkpoint_pipe[0]);
    if (rc != 0)
    {
        return fail_before_spawn(
            "posix_spawn_file_actions_addclose(read end) failed: " + std::string(std::strerror(rc)));
    }
    rc = ::posix_spawn_file_actions_adddup2(&file_actions, checkpoint_pipe[1], kChildLiftCheckpointFd);
    if (rc != 0)
    {
        return fail_before_spawn(
            "posix_spawn_file_actions_adddup2(checkpoint) failed: " + std::string(std::strerror(rc)));
    }
    rc = ::posix_spawn_file_actions_addclose(&file_actions, checkpoint_pipe[1]);
    if (rc != 0)
    {
        return fail_before_spawn(
            "posix_spawn_file_actions_addclose(write end) failed: " + std::string(std::strerror(rc)));
    }

    std::vector<std::string> child_args;
    child_args.reserve(16 + config.mutation_config.filter_categories.size());
    child_args.push_back(exe_path.string());
    child_args.push_back("--child-eval");
    append_flag_arg(child_args, "--child-so-path", item.so_path.string());
    append_flag_arg(child_args, "--child-func", item.func);
    append_flag_arg(child_args, "--child-addr", item.addr);
    append_flag_arg(child_args, "--child-result-path", result_path.string());
    append_flag_arg(child_args, "--child-lift-fd", kChildLiftCheckpointFd);
    append_flag_arg(child_args, "--child-deep-dives", config.deep_dive_count);
    append_flag_arg(child_args, "--child-run-raw-vs-native", config.run_raw_vs_native ? 1 : 0);
    append_flag_arg(child_args, "--child-run-opt-vs-raw", config.run_opt_vs_raw ? 1 : 0);
    append_flag_arg(child_args, "--child-run-eg3-strict", config.run_eg3_strict ? 1 : 0);
    append_flag_arg(child_args, "--child-run-eg3-relaxed", config.run_eg3_relaxed ? 1 : 0);
    append_flag_arg(child_args, "--child-run-mutation", config.run_mutation ? 1 : 0);
    append_flag_arg(child_args, "--child-mutation-budget", config.mutation_config.budget);
    append_flag_arg(child_args, "--child-mutation-seed", config.mutation_config.seed);
    append_flag_arg(child_args, "--child-lift-timeout-sec", config.lift_timeout_sec);
    if (!config.obfuscator.empty())
        append_flag_arg(child_args, "--child-obfuscator", config.obfuscator);
    for (auto category : config.mutation_config.filter_categories)
        append_flag_arg(child_args, "--child-mutation-category", mutation_category_arg(category));

    std::vector<char *> argv;
    argv.reserve(child_args.size() + 1);
    for (auto &arg : child_args)
        argv.push_back(arg.data());
    argv.push_back(nullptr);

    pid_t child_pid = -1;
    rc = ::posix_spawn(
        &child_pid, exe_path.c_str(), &file_actions, nullptr, argv.data(), environ);
    ::posix_spawn_file_actions_destroy(&file_actions);
    if (rc != 0)
    {
        close_fd_if_open(checkpoint_pipe[0]);
        close_fd_if_open(checkpoint_pipe[1]);
        return make_string_error(
            "posix_spawn failed for child evaluation: " + std::string(std::strerror(rc)));
    }

    close_fd_if_open(checkpoint_pipe[1]);

    bool lift_complete = false;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(config.lift_timeout_sec);
    while (!lift_complete)
    {
        pollfd pfd{};
        pfd.fd = checkpoint_pipe[0];
        pfd.events = POLLIN | POLLHUP | POLLERR;

        int timeout_ms = -1;
        if (config.lift_timeout_sec > 0)
        {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline)
            {
                close_fd_if_open(checkpoint_pipe[0]);
                kill_and_reap(child_pid);
                std::error_code remove_ec;
                fs::remove(result_path, remove_ec);
                return make_lift_status_record(
                    config,
                    LiftStatus::TIMEOUT,
                    "lift timed out before completion after " +
                        std::to_string(config.lift_timeout_sec) + "s");
            }

            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
            const auto bounded = std::min<int64_t>(
                std::numeric_limits<int>::max(),
                std::max<int64_t>(1, remaining.count()));
            timeout_ms = static_cast<int>(bounded);
        }

        int poll_rc = 0;
        do
        {
            poll_rc = ::poll(&pfd, 1, timeout_ms);
        } while (poll_rc < 0 && errno == EINTR);

        if (poll_rc < 0)
        {
            close_fd_if_open(checkpoint_pipe[0]);
            kill_and_reap(child_pid);
            std::error_code remove_ec;
            fs::remove(result_path, remove_ec);
            return make_string_error(
                "poll() failed while waiting for lift checkpoint: " +
                std::string(std::strerror(errno)));
        }
        if (poll_rc == 0)
        {
            close_fd_if_open(checkpoint_pipe[0]);
            kill_and_reap(child_pid);
            std::error_code remove_ec;
            fs::remove(result_path, remove_ec);
            return make_lift_status_record(
                config,
                LiftStatus::TIMEOUT,
                "lift timed out before completion after " +
                    std::to_string(config.lift_timeout_sec) + "s");
        }

        if (pfd.revents & POLLIN)
        {
            char marker = 0;
            ssize_t n = 0;
            do
            {
                n = ::read(checkpoint_pipe[0], &marker, 1);
            } while (n < 0 && errno == EINTR);
            if (n > 0)
            {
                lift_complete = true;
                break;
            }
        }

        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
            break;
    }

    close_fd_if_open(checkpoint_pipe[0]);

    int child_status = 0;
    while (::waitpid(child_pid, &child_status, 0) < 0)
    {
        if (errno == EINTR)
            continue;
        std::error_code remove_ec;
        fs::remove(result_path, remove_ec);
        return make_string_error(
            "waitpid() failed for child evaluation: " + std::string(std::strerror(errno)));
    }

    return read_child_result(item, result_path, child_status);
}

std::string fmt_dbl(double value, int precision = 1)
{
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", precision, value);
    return buffer;
}

std::vector<std::string> default_suite_order()
{
    std::vector<std::string> ordered;
    const std::vector<std::string> thesis_order = {
        "synthetic",
        "tum-basic-algorithms",
        "tum-small-programs",
        "tum-simple-hash-functions",
        "gnu-coreutils",
    };
    const auto known_names = known_suite_names();
    const std::set<std::string> known(known_names.begin(), known_names.end());
    for (const auto &suite : thesis_order)
        if (known.count(suite))
            ordered.push_back(suite);
    return ordered;
}

bool phase_failed(const VerificationPhaseResult &phase)
{
    return phase.status == PhaseStatus::FAIL || phase.status == PhaseStatus::ERROR;
}

bool mutation_failed(const MutationPhaseResult &mutation)
{
    return mutation.status == MutationPhaseStatus::ERROR ||
           (mutation.status == MutationPhaseStatus::SKIPPED &&
            mutation.skip_reason != "disabled" &&
            mutation.skip_reason != "lift timeout");
}

bool eg3_profile_failed(const Eg3ProfileResult &profile)
{
    return phase_failed(profile.selftest) || mutation_failed(profile.mutation);
}

void print_eg3_profile_summary(std::string_view label, const Eg3ProfileResult &profile)
{
    const char *profile_name = pipeline_checkpoint_profile_name(profile.profile);

    outs() << "  [EG3 " << label << " self-test/" << profile_name << "] "
           << phase_status_name(profile.selftest.status);
    if (!profile.selftest.skip_reason.empty())
        outs() << "  (" << profile.selftest.skip_reason << ")";
    else if (!profile.selftest.error.empty())
        outs() << "  (" << profile.selftest.error << ")";
    outs() << "\n";

    outs() << "  [EG3 " << label << " mutation/" << profile_name << "] "
           << mutation_phase_status_name(profile.mutation.status);
    if (profile.mutation.report)
    {
        outs() << "  (kill="
               << fmt_dbl(profile.mutation.report->mutation_score() * 100.0)
               << "% adj="
               << fmt_dbl(profile.mutation.report->adjusted_score() * 100.0)
               << "%)";
    }
    else if (!profile.mutation.skip_reason.empty())
    {
        outs() << "  (" << profile.mutation.skip_reason << ")";
    }
    else if (!profile.mutation.error.empty())
    {
        outs() << "  (" << profile.mutation.error << ")";
    }
    outs() << "\n";
}

int campaign_exit_code(const std::vector<EvaluatedFunction> &results)
{
    bool any_failure = false;
    for (const auto &entry : results)
    {
        if (entry.record.lift_status == LiftStatus::ERROR ||
            phase_failed(entry.record.raw_vs_native) ||
            phase_failed(entry.record.opt_vs_raw) ||
            eg3_profile_failed(entry.record.eg3_strict) ||
            eg3_profile_failed(entry.record.eg3_relaxed))
        {
            any_failure = true;
            continue;
        }
    }
    return any_failure ? 1 : 0;
}

void print_phase_summary(const EvaluatedFunction &entry)
{
    if (entry.record.lift_status == LiftStatus::ERROR)
    {
        outs() << "  [LIFTING] FAIL";
        if (!entry.record.lift_message.empty())
            outs() << "  (" << entry.record.lift_message << ")";
        outs() << "\n";
        return;
    }
    if (entry.record.lift_status == LiftStatus::TIMEOUT)
    {
        outs() << "  [LIFTING] TIMEOUT";
        if (!entry.record.lift_message.empty())
            outs() << "  (" << entry.record.lift_message << ")";
        outs() << "\n";
        return;
    }

    outs() << "  [EG1] " << phase_status_name(entry.record.raw_vs_native.status);
    if (!entry.record.raw_vs_native.skip_reason.empty())
        outs() << "  (" << entry.record.raw_vs_native.skip_reason << ")";
    outs() << "\n";

    outs() << "  [EG2] " << phase_status_name(entry.record.opt_vs_raw.status);
    if (!entry.record.opt_vs_raw.skip_reason.empty())
        outs() << "  (" << entry.record.opt_vs_raw.skip_reason << ")";
    outs() << "\n";

    print_eg3_profile_summary("strict", entry.record.eg3_strict);
    print_eg3_profile_summary("relaxed", entry.record.eg3_relaxed);
}

std::string standard_dir_name(const std::string &suite, std::string_view obfuscator)
{
    return suite + "_" + obfuscator_name(obfuscator);
}

std::string mutation_dir_name(const std::string &suite,
                              std::string_view obfuscator,
                              size_t budget)
{
    if (obfuscator.empty() && budget == 200)
        return suite + "_200";
    return suite + "_mut_" + obfuscator_name(obfuscator) + "_b" + std::to_string(budget);
}

} // namespace

int main(int argc, char **argv)
{
    FLAGS_minloglevel = 1;
    google::InitGoogleLogging(argv[0]);

    InitLLVM X(argc, argv);
    cl::HideUnrelatedOptions(LiftedEvalCategory);
    cl::ParseCommandLineOptions(argc, argv, "lifted-eval — batch evaluation runner\n");

    if (ChildEvalOpt)
        return run_child_evaluation_mode();

    if (WithStandardOpt && WithoutStandardOpt)
    {
        errs() << "lifted-eval error: cannot pass both --with-standard and --without-standard\n";
        return 2;
    }
    if (WithMutationOpt && WithoutMutationOpt)
    {
        errs() << "lifted-eval error: cannot pass both --with-mutation and --without-mutation\n";
        return 2;
    }

    const bool explicit_suite_filter = SuiteOpt.getNumOccurrences() > 0;
    std::vector<std::string> suites = explicit_suite_filter
        ? std::vector<std::string>(SuiteOpt.begin(), SuiteOpt.end())
        : default_suite_order();
    if (suites.empty())
    {
        errs() << "lifted-eval error: no suites available\n";
        return 2;
    }

    const auto known_names = known_suite_names();
    const std::set<std::string> known(known_names.begin(), known_names.end());
    for (const auto &suite : suites)
    {
        if (!known.count(suite))
        {
            errs() << "lifted-eval error: unknown suite '" << suite << "'\n";
            return 2;
        }
    }

    const bool run_standard = WithoutStandardOpt ? false : true;
    const bool run_mutation = WithoutMutationOpt ? false : true;
    const bool want_egs = AllEgsOpt || (!Eg1Opt && !Eg2Opt && !Eg3Opt);
    const bool want_eg1 = want_egs || Eg1Opt || Eg2Opt || Eg3Opt;
    const bool want_eg2 = want_egs || Eg2Opt || Eg3Opt;
    const bool want_eg3 = want_egs || Eg3Opt;

    if (!run_standard && !run_mutation)
    {
        errs() << "lifted-eval error: both standard and mutation campaigns are disabled\n";
        return 2;
    }

    MutationCampaignConfig mutation_cfg;
    mutation_cfg.budget = static_cast<size_t>(MutationBudgetOpt < 0 ? 200 : MutationBudgetOpt);
    try
    {
        mutation_cfg.seed = std::stoull(MutationSeedOpt, nullptr, 16);
    }
    catch (...)
    {
        errs() << "lifted-eval error: invalid mutation seed '" << MutationSeedOpt << "'\n";
        return 2;
    }
    for (const auto &cat_str : MutationCategoriesOpt)
    {
        auto cat = parse_category(cat_str);
        if (!cat)
        {
            errs() << "lifted-eval error: unknown mutation category '" << cat_str << "'\n";
            return 2;
        }
        mutation_cfg.filter_categories.push_back(*cat);
    }

    const std::set<std::string> target_filters(TargetOpt.begin(), TargetOpt.end());
    const std::set<std::string> func_filters(FuncOpt.begin(), FuncOpt.end());
    const std::set<std::string> ignore_filters(IgnoreOpt.begin(), IgnoreOpt.end());

    auto obfuscator_matches = [&](std::string_view obfuscator) -> bool
    {
        if (ObfuscatorOpt == "all")
            return true;
        if (ObfuscatorOpt == "none")
            return obfuscator.empty();
        return obfuscator == ObfuscatorOpt;
    };

    auto standard_config_for = [&](std::string_view obfuscator) {
        EvaluationConfig cfg;
        cfg.deep_dive_count = static_cast<size_t>(MaxDeepDivesOpt < 0 ? 0 : MaxDeepDivesOpt);
        cfg.obfuscator = std::string(obfuscator);
        cfg.run_raw_vs_native = want_eg1;
        cfg.run_opt_vs_raw = want_eg2;
        cfg.run_eg3_strict = want_eg3;
        cfg.run_eg3_relaxed = want_eg3;
        cfg.run_mutation = false;
        cfg.lift_timeout_sec = LiftTimeoutSecOpt;
        return cfg;
    };

    auto mutation_config_for = [&](std::string_view obfuscator) {
        EvaluationConfig cfg;
        cfg.deep_dive_count = static_cast<size_t>(MaxDeepDivesOpt < 0 ? 0 : MaxDeepDivesOpt);
        cfg.obfuscator = std::string(obfuscator);
        cfg.run_raw_vs_native = true;
        cfg.run_opt_vs_raw = true;
        cfg.run_eg3_strict = true;
        cfg.run_eg3_relaxed = true;
        cfg.run_mutation = true;
        cfg.mutation_config = mutation_cfg;
        cfg.lift_timeout_sec = LiftTimeoutSecOpt;
        return cfg;
    };

    std::vector<CampaignPlan> plans;
    for (const auto &suite : suites)
    {
        const bool default_suite_matrix = !explicit_suite_filter && ObfuscatorOpt == "all";
        std::vector<std::string> standard_obfuscators;
        if (default_suite_matrix && suite == "gnu-coreutils")
            standard_obfuscators = {""};
        else
            standard_obfuscators = {"", "polaris"};

        if (run_standard)
        {
            for (const auto &obfuscator : standard_obfuscators)
            {
                if (!obfuscator_matches(obfuscator))
                    continue;
                plans.push_back(CampaignPlan{
                    .suite = suite,
                    .obfuscator = obfuscator,
                    .mutation = false,
                    .output_dir = fs::path(std::string(OutputRootOpt)) / standard_dir_name(suite, obfuscator),
                    .config = standard_config_for(obfuscator),
                });
            }
        }

        if (run_mutation)
        {
            std::vector<std::string> mutation_obfuscators = {""};
            if (WithPolarisMutationOpt || ObfuscatorOpt == "polaris")
                mutation_obfuscators.push_back("polaris");
            for (const auto &obfuscator : mutation_obfuscators)
            {
                if (!obfuscator_matches(obfuscator))
                    continue;
                plans.push_back(CampaignPlan{
                    .suite = suite,
                    .obfuscator = obfuscator,
                    .mutation = true,
                    .output_dir = fs::path(std::string(OutputRootOpt)) / mutation_dir_name(suite, obfuscator, mutation_cfg.budget),
                    .config = mutation_config_for(obfuscator),
                });
            }
        }
    }

    if (plans.empty())
    {
        errs() << "lifted-eval error: no campaigns selected\n";
        return 2;
    }

    if (ListOpt)
    {
        outs() << "Planned campaigns:\n";
        for (const auto &plan : plans)
        {
            outs() << "  - suite=" << plan.suite
                   << " obfuscator=" << obfuscator_name(plan.obfuscator)
                   << " mode=" << (plan.mutation ? "mutation" : "standard")
                   << " out=" << plan.output_dir.string() << "\n";
        }
        return 0;
    }

    auto self_exe_or = current_executable_path(argv[0]);
    if (!self_exe_or)
    {
        errs() << "lifted-eval error: " << toString(self_exe_or.takeError()) << "\n";
        return 2;
    }
    const fs::path self_exe = *self_exe_or;
    const auto auto_job_count = []() -> size_t {
        const unsigned hint = std::thread::hardware_concurrency();
        return hint == 0 ? 1 : static_cast<size_t>(hint);
    };
    const auto configured_job_count = [&]() -> size_t {
        return JobsOpt <= 0 ? auto_job_count() : static_cast<size_t>(JobsOpt);
    };

    int overall_exit = 0;
    bool any_results = false;

    for (const auto &plan : plans)
    {
        auto suite_csv = resolve_suite_name(plan.suite);
        if (!suite_csv)
        {
            errs() << "lifted-eval error: cannot resolve suite '" << plan.suite << "'\n";
            return 2;
        }

        auto entries = parse_suite_csv(*suite_csv);
        if (entries.empty())
        {
            errs() << "lifted-eval error: no entries in suite '" << plan.suite << "'\n";
            return 2;
        }

        std::error_code ec;
        fs::create_directories(plan.output_dir, ec);
        if (ec)
        {
            errs() << "lifted-eval error: cannot create output dir '"
                   << plan.output_dir.string() << "': " << ec.message() << "\n";
            return 2;
        }

        outs() << "\n=== Campaign: " << plan.suite
               << " / " << obfuscator_name(plan.obfuscator)
               << " / " << (plan.mutation ? "mutation" : "standard")
               << " ===\n";

        std::vector<FunctionWorkItem> work_items;
        for (const auto &entry : entries)
        {
            if (entry.obfuscator != plan.obfuscator)
                continue;
            const std::string stem = target_stem(entry.so_path);
            if (!target_filters.empty() && !target_filters.count(stem))
                continue;
            if (ignore_filters.count(stem))
                continue;

            auto targets = parse_targets_csv(entry.targets_csv_path);
            for (const auto &target : targets)
            {
                const std::string label = stem + "::" + target.func_name;
                if (!func_filters.empty() && !func_filters.count(label))
                    continue;
                if (ignore_filters.count(label))
                    continue;

                work_items.push_back(FunctionWorkItem{
                    .ordinal = work_items.size() + 1,
                    .so_path = entry.so_path,
                    .binary = stem,
                    .func = target.func_name,
                    .addr = target.addr,
                });
            }
        }

        if (work_items.empty())
        {
            outs() << "  [SKIPPED] no matching functions for this campaign\n";
            continue;
        }

        any_results = true;
        const size_t jobs = std::max<size_t>(1, std::min(work_items.size(), configured_job_count()));
        outs() << "  [INFO] jobs=" << jobs << "\n";

        std::vector<std::optional<EvaluatedFunction>> ordered_results(work_items.size());
        std::vector<std::string> fatal_errors(work_items.size());
        std::atomic_size_t next_index{0};
        std::vector<std::thread> workers;
        workers.reserve(jobs);

        for (size_t worker = 0; worker < jobs; ++worker)
        {
            workers.emplace_back([&] {
                while (true)
                {
                    const size_t index = next_index.fetch_add(1);
                    if (index >= work_items.size())
                        break;

                    const auto &item = work_items[index];
                    auto record_or = run_evaluation_in_child(self_exe, item, plan.config);
                    if (!record_or)
                    {
                        fatal_errors[index] = toString(record_or.takeError());
                        continue;
                    }

                    ordered_results[index] = EvaluatedFunction{
                        .suite = plan.suite,
                        .binary = item.binary,
                        .func = item.func,
                        .obfuscator = obfuscator_name(plan.obfuscator),
                        .record = std::move(*record_or),
                    };
                }
            });
        }

        for (auto &worker : workers)
            worker.join();

        for (size_t index = 0; index < fatal_errors.size(); ++index)
        {
            if (!fatal_errors[index].empty())
            {
                errs() << "  [FATAL] " << fatal_errors[index] << "\n";
                return 2;
            }
            if (!ordered_results[index].has_value())
            {
                errs() << "  [FATAL] missing evaluation result for "
                       << work_items[index].binary << "::" << work_items[index].func << "\n";
                return 2;
            }
        }

        std::vector<EvaluatedFunction> results;
        results.reserve(ordered_results.size());
        for (size_t index = 0; index < ordered_results.size(); ++index)
        {
            const auto &item = work_items[index];
            outs() << "\n--- [" << item.ordinal << "/" << work_items.size() << "] "
                   << item.so_path.filename().string() << " :: " << item.func
                   << " @ " << llvm::format_hex(item.addr, 18) << " ---\n";

            results.push_back(std::move(*ordered_results[index]));
            print_phase_summary(results.back());
            write_function_reports(results.back(), plan.output_dir);
            write_function_dot(results.back(), plan.output_dir, RenderCfgOpt);
        }

        const std::string label = plan.suite + " (obfuscator=" + obfuscator_name(plan.obfuscator)
            + ", mode=" + (plan.mutation ? std::string("mutation") : std::string("standard")) + ")";
        write_campaign_artifacts(label, results, plan.output_dir);
        overall_exit = std::max(overall_exit, campaign_exit_code(results));
    }

    if (!any_results)
    {
        errs() << "lifted-eval error: filters excluded every function in every selected campaign\n";
        return 2;
    }

    return overall_exit;
}
