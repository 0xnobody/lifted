#pragma once

#include <cstdint>
#include <array>
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

// Forward declarations for LIEF types
namespace LIEF
{
    class Binary;
    namespace ELF
    {
        class Binary;
    }
    namespace PE
    {
        class Binary;
    }
}

struct mem_range_t
{
    uint64_t start; // inclusive
    uint64_t end;   // exclusive

    bool operator==(const mem_range_t &other) const
    {
        return start == other.start && end == other.end;
    }
    bool operator!=(const mem_range_t &other) const
    {
        return !(*this == other);
    }
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

    // Constructor for DYNAMIC pages (hash-seeded random content)
    page_t(uint64_t page_seed);

    // Constructor for IMAGE pages (content copied into page)
    page_t(std::array<uint8_t, 4096> content);

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
    static uint64_t compute_page_seed(uint64_t master_seed, uint64_t page_addr);

    // Try to load page content from binary image (ELF or PE)
    // Returns true if page_addr falls within a loadable segment/section
    bool try_load_image_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data);

    // Load a single page from ELF binary
    bool try_load_elf_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data);

    // Load a single page from PE binary
    bool try_load_pe_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data);

    // Get existing page or create one (IMAGE if in binary, else DYNAMIC)
    page_t &get_or_create_page(uint64_t page_addr);

public:
    // Constructor for dynamic-only memory state (no binary image)
    paged_memory_state(uint64_t seed);

    // Constructor with binary reference for lazy image loading
    paged_memory_state(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t base_addr);

    // Factory: create memory state with binary reference (lazy loading)
    static paged_memory_state init(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t base_addr = 0);

    // Create memory state with same seed and same binary reference
    // Pages are NOT copied - each instance lazily loads its own pages
    static paged_memory_state from_baseline(const paged_memory_state &baseline);

    // Factory: create from baseline with a different binary image
    static paged_memory_state from_baseline(const paged_memory_state &baseline,
                                            std::shared_ptr<LIEF::Binary> binary,
                                            uint64_t base_addr = 0);

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
    bool compare(const paged_memory_state &other, std::span<mem_range_t> ignored = {}) const;

    // Get statistics about page usage for debugging
    struct stats_t
    {
        size_t total_pages;
        size_t pages_with_writes;
        size_t total_bytes_written;
        size_t total_bytes_read;
    };

    stats_t get_stats() const;

    // Access pages for debugging/inspection
    const std::unordered_map<uint64_t, page_t> &get_pages() const { return pages; }
};
