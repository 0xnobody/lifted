
#include "paged_memory_state.hpp"

#include <LIEF/LIEF.hpp>

// page_t constructors

page_t::page_t(uint64_t page_seed)
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

page_t::page_t(std::array<uint8_t, 4096> content)
    : type(Type::IMAGE), data(std::move(content)), read{}, written{}
{
}

// paged_memory_state private methods

uint64_t paged_memory_state::compute_page_seed(uint64_t master_seed, uint64_t page_addr)
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

bool paged_memory_state::try_load_image_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data)
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

bool paged_memory_state::try_load_elf_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data)
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

bool paged_memory_state::try_load_pe_page(uint64_t page_addr, std::array<uint8_t, 4096> &out_data)
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

page_t &paged_memory_state::get_or_create_page(uint64_t page_addr)
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

// paged_memory_state public methods

paged_memory_state::paged_memory_state(uint64_t seed)
    : master_seed(seed), binary_(nullptr), image_base_(0)
{
}

paged_memory_state::paged_memory_state(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t base_addr)
    : master_seed(seed), binary_(std::move(binary)), image_base_(base_addr)
{
}

paged_memory_state paged_memory_state::init(uint64_t seed, std::shared_ptr<LIEF::Binary> binary, uint64_t base_addr)
{
    return paged_memory_state(seed, std::move(binary), base_addr);
}

paged_memory_state paged_memory_state::from_baseline(const paged_memory_state &baseline)
{
    return paged_memory_state(baseline.master_seed, baseline.binary_, baseline.image_base_);
}

paged_memory_state paged_memory_state::from_baseline(const paged_memory_state &baseline,
                                                     std::shared_ptr<LIEF::Binary> binary,
                                                     uint64_t base_addr)
{
    return init(baseline.master_seed, std::move(binary), base_addr);
}

bool paged_memory_state::compare(const paged_memory_state &other, std::span<mem_range_t> ignored) const
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

paged_memory_state::stats_t paged_memory_state::get_stats() const
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