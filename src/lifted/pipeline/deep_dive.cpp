#include "deep_dive.hpp"
#include "pipeline.hpp"

#include "../verification/comparator.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace lifted::pipeline
{

    // ── formatting helpers ────────────────────────────────────────────────────────

    namespace
    {

        using Detail = verification::checkpoint_detail_t;
        using Kind = verification::checkpoint_detail_t::kind;

        std::string hex64(uint64_t v)
        {
            char buf[20];
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
            return buf;
        }

        // Format the 7 most commonly relevant GPRs from a State.
        std::string format_regs(const State &s)
        {
            std::ostringstream ss;
            ss << "rax=" << hex64(s.gpr.rax.qword)
               << " rcx=" << hex64(s.gpr.rcx.qword)
               << " rdx=" << hex64(s.gpr.rdx.qword)
               << " rsi=" << hex64(s.gpr.rsi.qword)
               << " rdi=" << hex64(s.gpr.rdi.qword)
               << " rsp=" << hex64(s.gpr.rsp.qword)
               << " rbp=" << hex64(s.gpr.rbp.qword);
            return ss.str();
        }

        // Kind-to-type-prefix: "R8 ", "W16", "R64", etc.
        const char *mem_prefix(Kind k, uint32_t size)
        {
            if (k == Kind::MEM_READ)
            {
                switch (size)
                {
                case 1:
                    return "R8 ";
                case 2:
                    return "R16";
                case 4:
                    return "R32";
                default:
                    return "R64";
                }
            }
            else
            {
                switch (size)
                {
                case 1:
                    return "W8 ";
                case 2:
                    return "W16";
                case 4:
                    return "W32";
                default:
                    return "W64";
                }
            }
        }

        // Format a single detail record to a one-line string.
        std::string format_detail(const Detail &d)
        {
            std::ostringstream ss;
            switch (d.type)
            {
            case Kind::BB:
                ss << "BB   rva=" << hex64(d.addr);
                if (d.state)
                    ss << "  " << format_regs(*d.state);
                break;

            case Kind::MEM_READ:
            case Kind::MEM_WRITE:
                ss << mem_prefix(d.type, d.size)
                   << " addr=" << hex64(d.addr)
                   << "  val=" << hex64(d.value);
                break;

            case Kind::EXT_CALL:
                ss << "EXT  addr=" << hex64(d.addr);
                if (d.state)
                {
                    const State &s = *d.state;
                    // ABI argument registers (System V x86-64).
                    ss << "  rdi=" << hex64(s.gpr.rdi.qword)
                       << " rsi=" << hex64(s.gpr.rsi.qword)
                       << " rdx=" << hex64(s.gpr.rdx.qword)
                       << " rcx=" << hex64(s.gpr.rcx.qword)
                       << " r8=" << hex64(s.gpr.r8.qword)
                       << " r9=" << hex64(s.gpr.r9.qword)
                       << " rax=" << hex64(s.gpr.rax.qword);
                }
                break;
            }
            return ss.str();
        }

        struct RegDiff
        {
            const char *name;
            uint64_t src;
            uint64_t tgt;
        };

        // Return every GPR + rflag that differs between src and tgt.
        std::vector<RegDiff> diff_states(const State &src, const State &tgt)
        {
            std::vector<RegDiff> out;
            auto chk = [&](const char *n, uint64_t sv, uint64_t tv)
            {
                if (sv != tv)
                    out.push_back({n, sv, tv});
            };
            chk("rax", src.gpr.rax.qword, tgt.gpr.rax.qword);
            chk("rbx", src.gpr.rbx.qword, tgt.gpr.rbx.qword);
            chk("rcx", src.gpr.rcx.qword, tgt.gpr.rcx.qword);
            chk("rdx", src.gpr.rdx.qword, tgt.gpr.rdx.qword);
            chk("rsi", src.gpr.rsi.qword, tgt.gpr.rsi.qword);
            chk("rdi", src.gpr.rdi.qword, tgt.gpr.rdi.qword);
            chk("rbp", src.gpr.rbp.qword, tgt.gpr.rbp.qword);
            chk("rsp", src.gpr.rsp.qword, tgt.gpr.rsp.qword);
            chk("r8", src.gpr.r8.qword, tgt.gpr.r8.qword);
            chk("r9", src.gpr.r9.qword, tgt.gpr.r9.qword);
            chk("r10", src.gpr.r10.qword, tgt.gpr.r10.qword);
            chk("r11", src.gpr.r11.qword, tgt.gpr.r11.qword);
            chk("r12", src.gpr.r12.qword, tgt.gpr.r12.qword);
            chk("r13", src.gpr.r13.qword, tgt.gpr.r13.qword);
            chk("r14", src.gpr.r14.qword, tgt.gpr.r14.qword);
            chk("r15", src.gpr.r15.qword, tgt.gpr.r15.qword);
            chk("rflag", static_cast<uint64_t>(src.rflag.flat),
                static_cast<uint64_t>(tgt.rflag.flat));
            return out;
        }

        // Render event_flags bitmask as a human-readable string.
        std::string flags_str(verification::event_flags f)
        {
            using EF = verification::event_flags;
            std::string s;
            auto append = [&](const char *name, EF flag)
            {
                if (verification::has_flag(f, flag))
                {
                    if (!s.empty())
                        s += " | ";
                    s += name;
                }
            };
            append("BB", EF::BB);
            append("MEM_WRITE", EF::MEM_WRITE);
            append("MEM_READ", EF::MEM_READ);
            append("EXT_CALL", EF::EXT_CALL);
            if (s.empty())
                s = "NONE";
            return s;
        }

    } // anonymous namespace

    // ── Pipeline::deep_dive ───────────────────────────────────────────────────────

    llvm::Expected<DeepDiveResult> Pipeline::deep_dive(
        const RunOutcome &outcome,
        std::shared_ptr<LIEF::Binary> binary,
        uint64_t entry_rva,
        const DeepDiveConfig &cfg)
    {
        if (!src_executor_ || !tgt_executor_)
            return llvm::make_error<llvm::StringError>(
                "Pipeline::deep_dive() called before run() — executors not initialised",
                llvm::inconvertibleErrorCode());

        // Clone the diverging run's config and enable detail recording.
        // record_flags is preserved exactly from outcome.config so the checkpoint
        // sequence is identical to the original pipeline run — that is the only way
        // to reproduce the same NEEDS_RERUN path and expose the real divergence.
        RunConfig deep_cfg = outcome.config;
        deep_cfg.record_details = true;

        auto run_params = deep_cfg.to_run_params(binary, entry_rva);

        // ── src run (no prev_record) ──────────────────────────────────────────────
        auto src_verif = deep_cfg.to_verif_params(nullptr);
        auto src_result = src_executor_->run_single(run_params, src_verif);
        if (!src_result)
            return src_result.takeError();

        // ── tgt run (prev_record = src's checkpoint record) ───────────────────────
        auto tgt_verif = deep_cfg.to_verif_params(&src_result->checkpoint_record);
        auto tgt_result = tgt_executor_->run_single(run_params, tgt_verif);
        if (!tgt_result)
            return tgt_result.takeError();

        // ── compare ───────────────────────────────────────────────────────────────
        auto cmp = verification::compare_runs(*src_result, *tgt_result, spec_.compare_cfg);

        // ── NEEDS_RERUN: re-run src constrained to tgt's depth ───────────────────
        if (cmp.status == verification::comparison_status::NEEDS_RERUN)
        {
            auto src_verif2 = deep_cfg.to_verif_params(&tgt_result->checkpoint_record);
            auto src_result2 = src_executor_->run_single(run_params, src_verif2);
            if (!src_result2)
                return src_result2.takeError();
            *src_result = std::move(*src_result2);
            cmp = verification::compare_runs(*src_result, *tgt_result, spec_.compare_cfg);
        }

        return DeepDiveResult{
            .src_name = std::string(src_executor_->name()),
            .tgt_name = std::string(tgt_executor_->name()),
            .used_config = deep_cfg,
            .src_result = std::move(*src_result),
            .tgt_result = std::move(*tgt_result),
            .comparison = cmp,
            .pre_context = cfg.pre_context,
            .post_context = cfg.post_context,
        };
    }

    // ── DeepDiveResult::print ─────────────────────────────────────────────────────

    void DeepDiveResult::print(std::ostream &os) const
    {
        const auto &src_rec = src_result.checkpoint_record;
        const auto &tgt_rec = tgt_result.checkpoint_record;
        const auto &src_details = src_rec.details;
        const auto &tgt_details = tgt_rec.details;

        // Guard: detail recording must have been active.
        if (!src_rec.record_details || !tgt_rec.record_details)
        {
            os << "[deep-dive] detail recording was not enabled — nothing to display\n";
            return;
        }

        // Event counts (excluding sentinels at [0]).
        const size_t src_n = src_rec.event_count();
        const size_t tgt_n = tgt_rec.event_count();
        const size_t max_n = std::max(src_n, tgt_n);
        // First divergence index (1-based) — SIZE_MAX when none.
        size_t div_idx = SIZE_MAX;
        if (comparison.first_checkpoint_divergence)
            div_idx = comparison.first_checkpoint_divergence->index;

        // For depth-only divergences (no intra-checkpoint mismatch, but the two
        // sides have different event counts), synthesise a divergence index at the
        // first absent event so the table shows the extra side as <absent>.
        using CS = verification::comparison_status;
        if (div_idx == SIZE_MAX &&
            comparison.status == CS::FAIL_DIVERGED &&
            src_n != tgt_n)
        {
            div_idx = std::min(src_n, tgt_n) + 1;
        }

        // ── Status line ───────────────────────────────────────────────────────────
        using ET = verification::exit_type;
        auto et_name = [](ET t) -> const char *
        {
            switch (t)
            {
            case ET::NATURAL_EXIT:
                return "NATURAL_EXIT";
            case ET::EXCEPTION:
                return "EXCEPTION";
            case ET::MISSING_BLOCK:
                return "MISSING_BLOCK";
            case ET::CHECKPOINT_MISMATCH:
                return "CHECKPOINT_MISMATCH";
            case ET::LAST_CHECKPOINT_REACHED:
                return "LAST_CHECKPOINT_REACHED";
            case ET::LOOP_LIMIT:
                return "LOOP_LIMIT";
            case ET::BB_LIMIT:
                return "BB_LIMIT";
            }
            return "UNKNOWN";
        };

        switch (comparison.status)
        {
        case CS::PASS:
            os << "Status: PASS (divergence not reproduced in this re-run)\n";
            break;
        case CS::FAIL_DIVERGED:
            if (div_idx != SIZE_MAX)
                os << "Status: FAIL_DIVERGED \u2014 first divergence at checkpoint " << div_idx << "\n";
            else
                os << "Status: FAIL_DIVERGED \u2014 exit types differ"
                   << " (" << src_name << "=" << et_name(src_result.exit_reason)
                   << "  " << tgt_name << "=" << et_name(tgt_result.exit_reason) << ")\n";
            break;
        case CS::NEEDS_RERUN:
            os << "Status: NEEDS_RERUN \u2014 depths still differ after rerun"
               << " (" << src_name << "=" << src_n << " events"
               << "  " << tgt_name << "=" << tgt_n << " events)\n";
            break;
        case CS::FAIL_INCOMPARABLE:
            os << "Status: FAIL_INCOMPARABLE\n";
            break;
        }

        if (max_n == 0)
        {
            os << "(no events recorded)\n";
            return;
        }

        // ── Column header ─────────────────────────────────────────────────────────
        // W_SIDE is the max chars shown per-side.  Long formatted strings are truncated.
        constexpr int W_CHK = 5;
        constexpr int W_SIDE = 70;

        const std::string src_label = "Src (" + src_name + ")";
        const std::string tgt_label = "Tgt (" + tgt_name + ")";

        os << "\n"
           << std::setw(W_CHK) << "Chk"
           << "  " << std::left << std::setw(W_SIDE) << src_label
           << "  " << std::setw(W_SIDE) << tgt_label
           << "  Status\n"
           << std::right
           << std::string(static_cast<size_t>(W_CHK + 2 + W_SIDE + 2 + W_SIDE + 2 + 6), '-')
           << "\n";

        // ── Display range ─────────────────────────────────────────────────────────
        size_t lo = 1;
        size_t hi = max_n + 1; // exclusive upper bound

        if (div_idx != SIZE_MAX && (pre_context > 0 || post_context > 0))
        {
            lo = (div_idx > pre_context) ? (div_idx - pre_context) : 1;
            hi = std::min(div_idx + post_context + 1, max_n + 1);
        }

        if (lo > 1)
            os << "  ... (" << (lo - 1) << " events omitted) ...\n";

        bool printed_banner = false;

        for (size_t i = lo; i < hi; ++i)
        {
            // Divergence banner immediately before the first diverging event.
            if (i == div_idx && !printed_banner)
            {
                printed_banner = true;
                os << "\n>>> FIRST DIVERGENCE AT CHECKPOINT " << div_idx << " <<<\n\n";
            }

            const Detail *sd = (i < src_details.size()) ? &src_details[i] : nullptr;
            const Detail *td = (i < tgt_details.size()) ? &tgt_details[i] : nullptr;

            const bool diverged = (i >= div_idx);
            const char *status = diverged ? "[!]" : "[=]";

            std::string src_str = sd ? format_detail(*sd) : "<absent>";
            std::string tgt_str;

            if (!diverged)
                tgt_str = "(same)";
            else
                tgt_str = td ? format_detail(*td) : "<absent>";

            // Truncate to column width before printing.
            if (src_str.size() > static_cast<size_t>(W_SIDE))
                src_str.resize(static_cast<size_t>(W_SIDE));
            if (tgt_str.size() > static_cast<size_t>(W_SIDE))
                tgt_str.resize(static_cast<size_t>(W_SIDE));

            os << std::setw(W_CHK) << i
               << "  " << std::left << std::setw(W_SIDE) << src_str
               << "  " << std::setw(W_SIDE) << tgt_str
               << "  " << status << "\n"
               << std::right;

            // For diverging BB / EXT_CALL events with States on both sides, print
            // a follow-up line listing only the registers that differ.
            if (diverged && sd && td && sd->state && td->state &&
                (sd->type == Kind::BB || sd->type == Kind::EXT_CALL))
            {
                auto diffs = diff_states(*sd->state, *td->state);
                if (!diffs.empty())
                {
                    os << std::string(static_cast<size_t>(W_CHK + 2), ' ') << "^ ";
                    bool first = true;
                    for (const auto &d : diffs)
                    {
                        if (!first)
                            os << "  ";
                        os << d.name << ": src=" << hex64(d.src)
                           << " tgt=" << hex64(d.tgt);
                        first = false;
                    }
                    os << "\n";
                }
            }
        }

        if (hi <= max_n)
            os << "  ... (" << (max_n - hi + 1) << " events omitted) ...\n";

        os << "\n";
    }

} // namespace lifted::pipeline
