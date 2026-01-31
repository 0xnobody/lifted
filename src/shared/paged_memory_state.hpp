#pragma once

#include <LIEF/LIEF.hpp>

#include <unordered_map>
#include <random>
#include <vector>
#include <algorithm>
#include <iostream>
#include <bitset>
#include <span>
#include <stdexcept>
#include <sstream>
#include <memory>

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

    // Constructor for DYNAMIC pages (hash-seeded random content)
    page_t(uint64_t page_seed)
        : type(Type::DYNAMIC), data{}, read{}, written{}
    {
        // Initialize data with random values based on page-specific seed
        std::mt19937_64 rng(page_seed);
        std::uniform_int_distribution<uint8_t> dis(0, 0xFF);
        for (size_t i = 0; i < data.size(); ++i)
        {
            data[i] = dis(rng);
        }
    }

    // Constructor for IMAGE pages (content copied into page)
    page_t(std::array<uint8_t, 4096> content)
        : type(Type::IMAGE), data(std::move(content)), read{}, written{}
    {
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

class paged_memory_state
{
private:
    std::unordered_map<uint64_t, page_t> pages;
    uint64_t master_seed;

    // Lazy image loading: store reference to binary and base address
    std::shared_ptr<LIEF::Binary> binary_;
    uint64_t image_base_ = 0;

    // Deterministic hash combining master_seed and page_addr
    // Uses a simple but effective mixing based on golden ratio prime
    static uint64_t compute_page_seed(uint64_t master_seed, uint64_t page_addr)
    {
        // Mix page_addr into master_seed using multiplication and xor
        // 0x9e3779b97f4a7c15 is derived from golden ratio (good for hashing)
        uint64_t mixed = master_seed ^ (page_addr * 0x9e3779b97f4a7c15ULL);
        // Additional mixing to improve distribution
        mixed ^= mixed >> 33;
        mixed *= 0xff51afd7ed558ccdULL;
        mixed ^= mixed >> 33;
        return mixed;
    }

    // Try to load page content from binary image (ELF or PE)
    // Returns true if page_addr falls within a loadable segment/section
    bool try_load_image_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data)
    {
        if (!binary_)
            return false;

        if (binary_->format() == LIEF::EXE_FORMATS::FORMAT_ELF)
        {
            return try_load_elf_page(page_addr, out_data);
        }
        else if (binary_->format() == LIEF::EXE_FORMATS::FORMAT_PE)
        {
            return try_load_pe_page(page_addr, out_data);
        }

        return false;
    }

    // Load a single page from ELF binary
    bool try_load_elf_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data)
    {
        auto &elf = dynamic_cast<LIEF::ELF::Binary &>(*binary_);
        bool found = false;
        out_data.fill(0);

        for (auto &segment : elf.segments())
        {
            if (segment.type() != LIEF::ELF::SEGMENT_TYPES::PT_LOAD)
                continue;

            uint64_t seg_start = segment.virtual_address() + image_base_;
            uint64_t seg_end = seg_start + segment.virtual_size();

            // Check if page overlaps with this segment
            uint64_t page_end = page_addr + 0x1000;
            if (page_end <= seg_start || page_addr >= seg_end)
                continue;

            // Calculate overlap
            uint64_t overlap_start = std::max(page_addr, seg_start);
            uint64_t overlap_end = std::min(page_end, seg_end);
            uint64_t page_offset = overlap_start - page_addr;
            uint64_t seg_offset = overlap_start - seg_start;
            uint64_t copy_size = overlap_end - overlap_start;

            // Copy from segment content (may be smaller than virtual_size for .bss)
            auto content = segment.content();
            if (seg_offset < content.size())
            {
                size_t available = content.size() - seg_offset;
                size_t to_copy = std::min(copy_size, available);
                std::copy_n(content.begin() + seg_offset, to_copy, out_data.begin() + page_offset);
            }
            // Remaining bytes in overlap stay zero (BSS behavior)

            found = true;
            // Continue to handle overlapping segments (merge non-zero)
        }

        return found;
    }

    // Load a single page from PE binary
    bool try_load_pe_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data)
    {
        auto &pe = dynamic_cast<LIEF::PE::Binary &>(*binary_);
        uint64_t pe_base = pe.imagebase();
        bool found = false;
        out_data.fill(0);

        for (auto &section : pe.sections())
        {
            uint64_t sec_start = pe_base + section.virtual_address();
            uint64_t sec_end = sec_start + section.virtual_size();

            uint64_t page_end = page_addr + 0x1000;
            if (page_end <= sec_start || page_addr >= sec_end)
                continue;

            uint64_t overlap_start = std::max(page_addr, sec_start);
            uint64_t overlap_end = std::min(page_end, sec_end);
            uint64_t page_offset = overlap_start - page_addr;
            uint64_t sec_offset = overlap_start - sec_start;
            uint64_t copy_size = overlap_end - overlap_start;

            auto content = section.content();
            if (sec_offset < content.size())
            {
                size_t available = content.size() - sec_offset;
                size_t to_copy = std::min(copy_size, available);
                std::copy_n(content.begin() + sec_offset, to_copy, out_data.begin() + page_offset);
            }

            found = true;
        }

        return found;
    }

    // Get existing page or create one (IMAGE if in binary, else DYNAMIC)
    page_t &get_or_create_page(uint64_t page_addr)
    {
        auto it = pages.find(page_addr);
        if (it != pages.end())
        {
            return it->second;
        }

        // Try to load from binary image first
        std::array<uint8_t, 4096> image_data;
        if (try_load_image_page(page_addr, image_data))
        {
            auto [new_it, _] = pages.emplace(page_addr, page_t(std::move(image_data)));
            return new_it->second;
        }

        // Create new DYNAMIC page with hash-based seed
        uint64_t page_seed = compute_page_seed(master_seed, page_addr);
        auto [new_it, _] = pages.emplace(page_addr, page_t(page_seed));
        return new_it->second;
    }

public:
    // Constructor for dynamic-only memory state (no binary image)
    paged_memory_state(uint64_t seed)
        : master_seed(seed), binary_(nullptr), image_base_(0)
    {
    }

    // Constructor with binary reference for lazy image loading
    paged_memory_state(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t base_addr)
        : master_seed(seed), binary_(std::move(binary)), image_base_(base_addr)
    {
    }

    // Factory: create memory state with binary reference (lazy loading)
    static paged_memory_state init(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t base_addr = 0)
    {
        uint64_t effective_base = base_addr;

        // Handle ELF shared objects that need a base address
        if (binary && binary->format() == LIEF::EXE_FORMATS::FORMAT_ELF)
        {
            auto &elf = dynamic_cast<LIEF::ELF::Binary &>(*binary);
            if (base_addr == 0 && elf.header().file_type() == LIEF::ELF::E_TYPE::ET_DYN)
            {
                // Caller should specify base_addr for PIE/shared objects
                effective_base = 0;
            }
        }

        return paged_memory_state(seed, std::move(binary), effective_base);
    }

    // Create memory state with same seed and same binary reference
    // Pages are NOT copied - each instance lazily loads its own pages
    static paged_memory_state from_baseline(const paged_memory_state &baseline)
    {
        return paged_memory_state(baseline.master_seed, baseline.binary_, baseline.image_base_);
    }

    // Factory: create from baseline with a different binary image
    static paged_memory_state from_baseline(const paged_memory_state &baseline,
                                            std::shared_ptr<LIEF::Binary> binary,
                                            uint64_t base_addr = 0)
    {
        return init(baseline.master_seed, std::move(binary), base_addr);
    }

    uint64_t get_master_seed() const { return master_seed; }
    uint64_t get_image_base() const { return image_base_; }
    const std::shared_ptr<LIEF::Binary> &get_binary() const { return binary_; }

    std::span<uint8_t, 4096> map(uint64_t addr)
    {
        uint64_t page_addr = addr & ~0xFFFULL;
        return get_or_create_page(page_addr).data;
    }

    uint8_t read8(uint64_t addr)
    {
        uint64_t page_addr = addr & ~0xFFFULL;
        uint64_t offset = addr & 0xFFFULL;
        return get_or_create_page(page_addr).read8(offset);
    }

    // TODO: can later optimize this to avoid repeated page lookups
    uint16_t read16(uint64_t addr)
    {
        uint16_t v = 0;
        v |= read8(addr + 0) << 0;
        v |= read8(addr + 1) << 8;
        return v;
    }

    uint32_t read32(uint64_t addr)
    {
        uint32_t v = 0;
        v |= read16(addr + 0) << 0;
        v |= read16(addr + 2) << 16;
        return v;
    }

    uint64_t read64(uint64_t addr)
    {
        uint64_t v = 0;
        v |= (uint64_t)read32(addr + 0) << 0;
        v |= (uint64_t)read32(addr + 4) << 32;
        return v;
    }

    void write8(uint64_t addr, uint8_t val)
    {
        uint64_t page_addr = addr & ~0xFFFULL;
        uint64_t offset = addr & 0xFFFULL;
        get_or_create_page(page_addr).write8(offset, val);
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

    // Symmetric comparison: only written bytes must match
    //
    // This function IS commutative - a.compare(b) == b.compare(a)
    //
    // Requirements:
    // 1. Same write set: the set of written byte addresses must be identical
    // 2. Same written values: all written bytes must have the same final values
    //
    // What we DON'T require:
    // - Same pages accessed (reads are internal behavior)
    // - Same read patterns
    //
    // Returns: true if equivalent, false otherwise
    bool compare(const paged_memory_state &other, std::span<mem_range_t> ignored = {}) const
    {
        auto is_page_ignored = [&](uint64_t page_addr) -> bool
        {
            for (const auto &range : ignored)
            {
                // Page [page_addr, page_addr+4096) overlaps with [range.start, range.end)
                if (page_addr + 4096 > range.start && page_addr < range.end)
                {
                    return true;
                }
            }
            return false;
        };

        // Collect all page addresses that have writes from either side
        std::vector<uint64_t> pages_with_writes;
        for (const auto &[page_addr, page] : pages)
        {
            if (!is_page_ignored(page_addr) && page.written.any())
            {
                pages_with_writes.push_back(page_addr);
            }
        }
        for (const auto &[page_addr, page] : other.pages)
        {
            if (!is_page_ignored(page_addr) && page.written.any())
            {
                // Only add if not already tracked from our pages
                auto it = pages.find(page_addr);
                if (it == pages.end() || !it->second.written.any())
                {
                    pages_with_writes.push_back(page_addr);
                }
            }
        }

        // For each page with writes, verify written bytes match
        static const std::bitset<4096> empty_written{};

        for (uint64_t page_addr : pages_with_writes)
        {
            auto it_a = pages.find(page_addr);
            auto it_b = other.pages.find(page_addr);

            const auto &written_a = (it_a != pages.end()) ? it_a->second.written : empty_written;
            const auto &written_b = (it_b != other.pages.end()) ? it_b->second.written : empty_written;

            // Written byte sets must be identical
            if (written_a != written_b)
            {
                return false;
            }

            // Compare actual values of written bytes
            if (written_a.any())
            {
                const auto &data_a = it_a->second.data;
                const auto &data_b = it_b->second.data;

                for (size_t i = 0; i < 4096; ++i)
                {
                    if (written_a.test(i) && data_a[i] != data_b[i])
                    {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    // Get statistics about page usage for debugging
    struct stats_t
    {
        size_t total_pages;
        size_t pages_with_writes;
        size_t total_bytes_written;
        size_t total_bytes_read;
    };

    stats_t get_stats() const
    {
        stats_t s{};
        s.total_pages = pages.size();
        for (const auto &[_, page] : pages)
        {
            if (page.written.any())
            {
                s.pages_with_writes++;
            }
            s.total_bytes_written += page.written.count();
            s.total_bytes_read += page.read.count();
        }
        return s;
    }

    // Access pages for debugging/inspection
    const std::unordered_map<uint64_t, page_t> &get_pages() const { return pages; }
};
