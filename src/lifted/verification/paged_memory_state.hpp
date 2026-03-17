#pragma once

#include "sentinel_oracle.hpp"
#include "value_generator.hpp"
#include "../binary_context.hpp"
#include "../hash_mix.hpp"

#include <cstdint>
#include <array>
#include <unordered_map>
#include <optional>
#include <random>
#include <vector>
#include <algorithm>
#include <iostream>
#include <bitset>
#include <span>
#include <stdexcept>
#include <sstream>
#include <memory>

#include <llvm/ADT/AddressRanges.h>

namespace lifted::verification
{
    struct memory_range_diff_t
    {
        uint64_t start; // absolute virtual address (inclusive)
        uint64_t end;   // absolute virtual address (exclusive)
        std::vector<uint8_t> data_a;
        std::vector<uint8_t> data_b;
    };

    enum class page_diff_kind : uint8_t
    {
        VALUE_MISMATCH = 1 << 0,     // same write set, different values
        WRITE_SET_MISMATCH = 1 << 1, // different bytes were written
        BOTH = VALUE_MISMATCH | WRITE_SET_MISMATCH,
    };

    struct page_diff_t
    {
        uint64_t page_addr;
        page_diff_kind kind;
        std::bitset<4096> written_a;
        std::bitset<4096> written_b;
        std::vector<memory_range_diff_t> ranges; // collapsed consecutive differing bytes
    };

    struct memory_diff_result_t
    {
        bool equivalent;
        std::vector<page_diff_t> page_diffs;
    };

    struct memory_contents_digest_t
    {
        uint64_t written_set_hash = 0;
        uint64_t written_value_hash = 0;

        uint64_t combined_hash() const noexcept
        {
            return hash::mix_many(written_set_hash, written_value_hash);
        }

        bool operator==(const memory_contents_digest_t &other) const noexcept = default;
    };

    //
    // Paged memory state for verification runs.
    //
    // Two types of pages:
    // - IMAGE pages: Lazily loaded from binary (ELF/PE) on first access
    // - DYNAMIC pages: Lazily created, deterministic via HASH(master_seed, page_addr)
    //
    // Key design:
    // - Order of page accesses doesn't matter - same page always gets same initial content
    // - Only need master_seed + binary reference to recreate the entire memory state
    // - Comparison is symmetric (commutative) - only written bytes matter
    // - Reads are internal behavior and don't affect equivalence
    // - Fully lazy: pages are only materialized when accessed
    //

    // Byte-level granularity: we log each read/write for precise tracking.
    // This is slower but gives us exact information about which addresses were accessed.

    struct page_t
    {
        enum class Type
        {
            IMAGE,
            DYNAMIC
        };

        Type type;
        std::array<uint8_t, 4096> data;
        std::bitset<4096> read;
        std::bitset<4096> written;
        // Set when a sentinel oracle has injected a value at this byte.
        // Prevents re-querying the oracle and overwriting already-committed sentinel bytes.
        std::bitset<4096> sentinel_filled;

        // Constructor for DYNAMIC pages (hash-seeded random content)
        page_t(uint64_t page_seed);

        // Constructor for IMAGE pages (content copied into page)
        page_t(std::array<uint8_t, 4096> content);

        // Constructor for factory-filled DYNAMIC pages (pre-generated content, explicit type tag)
        page_t(std::array<uint8_t, 4096> content, Type t);

        // Write byte without touching 'written' or 'sentinel_filled' — for sentinel injection.
        void raw_write8(uint64_t offset, uint8_t val)
        {
            data[offset] = val;
        }

        void write8(uint64_t offset, uint8_t val)
        {
            data[offset] = val;
            written.set(offset);
        }

        uint8_t read8(uint64_t offset)
        {
            read.set(offset);
            return data[offset];
        }

        bool is_written(uint64_t offset) const
        {
            return written.test(offset);
        }

        bool is_read(uint64_t offset) const
        {
            return read.test(offset);
        }
    };

    // Lightweight post-run snapshot — holds only the materialized pages and the
    // comparison / stats API.  Produced by paged_memory_state::finalize() and
    // stored in run_result_t.  No binary ref, no seed, no oracle.
    struct memory_snapshot_t
    {
        std::unordered_map<uint64_t, page_t> pages;
        memory_contents_digest_t digest;

        struct stats_t
        {
            size_t total_pages;
            size_t pages_with_writes;
            size_t total_bytes_written;
            size_t total_bytes_read;
        };

        bool compare(const memory_snapshot_t &other, std::span<const llvm::AddressRange> ignored = {}) const;
        memory_diff_result_t compare_detailed(const memory_snapshot_t &other, std::span<const llvm::AddressRange> ignored = {}) const;
        stats_t get_stats() const;
        const std::unordered_map<uint64_t, page_t> &get_pages() const { return pages; }
        memory_contents_digest_t memory_contents_digest() const noexcept { return digest; }
    };

    class paged_memory_state
    {
    private:
        std::unordered_map<uint64_t, page_t> pages;
        uint64_t master_seed;
        memory_contents_digest_t digest_{};

        // Lazy image loading: non-owning pointer to BinaryContext.
        const lifted::BinaryContext *bin_ctx_ = nullptr;
        uint64_t image_base_ = 0;

        // Non-owning pointers — valid only during execution; both outlive this object.
        const sentinel_oracle *oracle_ = nullptr;
        const value_generator_factory *value_gen_factory_ = nullptr;

        // Separate hash for oracle slot seeds — same mixing, different salt,
        // so oracle rolls are uncorrelated with initial page data fills.
        // Public so verifier_state can derive deterministic per-register seeds.
        static uint64_t compute_oracle_slot_seed(uint64_t master_seed, uint64_t slot_addr);

        // Deterministic hash combining master_seed and page_addr
        // Uses a simple but effective mixing based on golden ratio prime
        static uint64_t compute_page_seed(uint64_t master_seed, uint64_t page_addr);

        // Order-insensitive memory-content digest contributions.
        static uint64_t written_set_contribution(uint64_t addr);
        static uint64_t written_value_contribution(uint64_t addr, uint8_t value);
        void note_byte_write(uint64_t addr, page_t &page, uint64_t offset, uint8_t value);

        // Try to load page content from binary image (ELF or PE)
        // Returns true if page_addr falls within a loadable segment/section
        bool try_load_image_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data);

        // Load a single page from ELF binary
        bool try_load_elf_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data);

        // Load a single page from PE binary
        bool try_load_pe_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data);

        // Get existing page or create one (IMAGE if in binary, else DYNAMIC)
        page_t &get_or_create_page(uint64_t page_addr);

        // Try to inject a sentinel into a single-page multi-byte read.
        // N bytes starting at (page, offset) must all lie within one page.
        // Only injects if none of the N bytes are already sentinel_filled.
        // Marks injected bytes as sentinel_filled in the page.
        template <typename T, uint8_t N>
        void try_inject_sentinel(page_t &page, uint64_t offset, uint64_t addr)
        {
            static_assert(N == 1 || N == 2 || N == 4 || N == 8);
            // IMAGE pages hold known binary content (code, data, relocated slots).
            // Injecting sentinel values here would override e.g. relocation-patched
            // jump-table entries that the JIT has already folded away via CMFP.
            // The oracle is only meaningful for DYNAMIC (uninitialised) memory.
            if (page.type == page_t::Type::IMAGE)
                return;
            // Check: if ANY byte in [offset, offset+N) is already sentinel_filled OR written
            // by the program, skip injection. Sentinel never overwrites program writes.
            bool any_filled = false;
            for (uint8_t i = 0; i < N; ++i)
                any_filled |= page.sentinel_filled.test(offset + i) | page.written.test(offset + i);
            if (any_filled)
                return;

            // Compute a stable slot seed aligned to the access size.
            uint64_t slot_addr = addr & ~(uint64_t)(N - 1);
            uint64_t slot_seed = compute_oracle_slot_seed(master_seed, slot_addr);
            auto s = oracle_->query(slot_seed, N);
            if (!s)
                return;

            T val = (T)s->value;
            for (uint8_t i = 0; i < N; ++i)
            {
                page.raw_write8(offset + i, (uint8_t)(val >> (i * 8)));
                page.sentinel_filled.set(offset + i);
            }
        }

        // Core multi-byte read: single-page path with sentinel injection + cross-page fallback.
        template <typename T, uint8_t N>
        T read_sized(uint64_t addr)
        {
            static_assert(sizeof(T) == N);

            // Cross-page slow path — very rare (~N/4096 probability for random addr).
            if ((addr & 0xFFFULL) + N > 0x1000ULL) [[unlikely]]
            {
                // Oracle injection at size=1 per byte is handled by read8().
                T v = 0;
                for (uint8_t i = 0; i < N; ++i)
                    v |= (T)read8(addr + i) << (i * 8);
                return v;
            }

            uint64_t page_addr = addr & ~0xFFFULL;
            uint64_t offset = addr & 0xFFFULL;
            page_t &page = get_or_create_page(page_addr);

            if (oracle_)
                try_inject_sentinel<T, N>(page, offset, addr);

            // Read N bytes directly from the page and mark them read.
            T v = 0;
            for (uint8_t i = 0; i < N; ++i)
            {
                v |= (T)page.data[offset + i] << (i * 8);
                page.read.set(offset + i);
            }
            return v;
        }

    public:
        // Constructor for dynamic-only memory state (no binary image)
        paged_memory_state(uint64_t seed, const sentinel_oracle *oracle = nullptr, const value_generator_factory *gen_factory = nullptr);

        // Constructor with BinaryContext for lazy image loading
        paged_memory_state(uint64_t seed, const lifted::BinaryContext *bin_ctx, uint64_t base_addr, const sentinel_oracle *oracle = nullptr, const value_generator_factory *gen_factory = nullptr);
        // Consume this transient execution object and extract the pages into a
        // lightweight snapshot suitable for storage in run_result_t.
        static memory_snapshot_t finalize(paged_memory_state &&mem);

        uint64_t get_master_seed() const { return master_seed; }
        uint64_t get_image_base() const { return image_base_; }
        memory_contents_digest_t memory_contents_digest() const noexcept { return digest_; }

        std::span<uint8_t, 4096> map(uint64_t addr)
        {
            uint64_t page_addr = addr & ~0xFFFULL;
            return get_or_create_page(page_addr).data;
        }

        uint8_t read8(uint64_t addr)
        {
            uint64_t page_addr = addr & ~0xFFFULL;
            uint64_t offset = addr & 0xFFFULL;
            page_t &page = get_or_create_page(page_addr);

            // Same guard as try_inject_sentinel: skip IMAGE pages.
            if (oracle_ && page.type != page_t::Type::IMAGE &&
                !page.sentinel_filled.test(offset) && !page.written.test(offset))
            {
                uint64_t slot_seed = compute_oracle_slot_seed(master_seed, addr);
                if (auto s = oracle_->query(slot_seed, 1))
                {
                    page.raw_write8(offset, (uint8_t)s->value);
                    page.sentinel_filled.set(offset);
                }
}

            return page.read8(offset);
        }

        uint16_t read16(uint64_t addr) { return read_sized<uint16_t, 2>(addr); }
        uint32_t read32(uint64_t addr) { return read_sized<uint32_t, 4>(addr); }
        uint64_t read64(uint64_t addr) { return read_sized<uint64_t, 8>(addr); }

        void write8(uint64_t addr, uint8_t val)
        {
            uint64_t page_addr = addr & ~0xFFFULL;
            uint64_t offset = addr & 0xFFFULL;
            page_t &page = get_or_create_page(page_addr);
            note_byte_write(addr, page, offset, val);
        }

        void write16(uint64_t addr, uint16_t val)
        {
            write8(addr + 0, (val >> 0) & 0xFF);
            write8(addr + 1, (val >> 8) & 0xFF);
        }

        void write32(uint64_t addr, uint32_t val)
        {
            write16(addr + 0, (val >> 0) & 0xFFFF);
            write16(addr + 2, (val >> 16) & 0xFFFF);
        }

        void write64(uint64_t addr, uint64_t val)
        {
            write32(addr + 0, (val >> 0) & 0xFFFFFFFF);
            write32(addr + 4, (val >> 32) & 0xFFFFFFFF);
        }

        // Set or clear the sentinel oracle pointer (non-owning).
        // Valid only during execution; caller must ensure oracle outlives this object.
        void set_oracle(const sentinel_oracle *oracle) { oracle_ = oracle; }
        const sentinel_oracle *get_oracle() const { return oracle_; }

        // Set or clear the value generator factory pointer (non-owning).
        // Affects future DYNAMIC page creation; already-materialized pages are unaffected.
        void set_value_generator_factory(const value_generator_factory *f) { value_gen_factory_ = f; }
        const value_generator_factory *get_value_generator_factory() const { return value_gen_factory_; }

        // Raw page access for inspection/testing during execution.
        const std::unordered_map<uint64_t, page_t> &get_pages() const { return pages; }
    };
}