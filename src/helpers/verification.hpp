#pragma once

#include <unordered_map>
#include <random>
#include <vector>
#include <algorithm>
#include <iostream>

//
// The idea is that optimizations can modify the order of mem reads/writes in certain scenarios,
// so if we run two versions of the program with the same initial seed, and lazily initialize memory
// randomly on the first read, the values might differ between the two runs if the order of reads differ.
//
// So instead of that, we only lazily generate once, on the first run, and store the initial memory state.
// Then, on the second run, we use that initial memory state to ensure both runs see the same values on reads.
//

class rand_memory_state
{
public:
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

    struct mem_block_t
    {
        uint8_t val;
        bool written;

        bool operator==(const mem_block_t &other) const
        {
            return val == other.val && written == other.written;
        }
        bool operator!=(const mem_block_t &other) const
        {
            return !(*this == other);
        }
    };

    using mem_state_t = std::unordered_map<uint64_t, mem_block_t>;

private:
    mem_state_t memory_initial;
    mem_state_t memory;

    // random
    std::mt19937_64 *rng;
    std::uniform_int_distribution<uint8_t> dis;

public:
    rand_memory_state(std::mt19937_64 *rng)
        : rng(rng), dis(0, 0xFF)
    {
    }
    rand_memory_state(const mem_state_t &memory_initial)
        : rng(nullptr), memory(memory_initial), dis(0, 0xFF)
    {
    }

    void debug_memory_state(FILE *out = stdout)
    {
        for (const auto &[addr, block] : memory)
        {
            fprintf(out, "Addr: %p Val: %02x Written: %d\n", (void *)addr, block.val, block.written);
        }
    }

    bool compare_memory_state(const rand_memory_state &other, const std::vector<mem_range_t> &ignored = {})
    {
        for (const auto &mem : memory)
        {
            const uint64_t addr = mem.first;
            const auto &block = mem.second;

            if (std::find_if(ignored.begin(), ignored.end(), [&](const mem_range_t &range)
                             { return addr >= range.start && addr < range.end; }) != ignored.end())
            {
                continue;
            }

            auto it = other.memory.find(addr);
            if (it == other.memory.end())
            {
                return false;
            }
            else
            {
                const auto &other_block = it->second;
                if (block != other_block)
                {
                    return false;
                }
            }
        }
        return true;
    }

    void debug_compare_memory_state(const rand_memory_state &other, FILE *out = stdout)
    {
        for (const auto &[addr, block] : memory)
        {
            auto it = other.memory.find(addr);
            if (it == other.memory.end())
            {
                fprintf(out, "Addr: %p Val: %02x Written: %d | MISSING in other\n", (void *)addr, block.val, block.written);
            }
            else
            {
                const auto &other_block = it->second;
                if (block.val != other_block.val || block.written != other_block.written)
                {
                    fprintf(out, "Addr: %p Val: %02x Written: %d | OTHER Val: %02x Written: %d\n",
                            (void *)addr,
                            block.val, block.written,
                            other_block.val, other_block.written);
                }
            }
        }
    }

    mem_state_t get_initial_state()
    {
        return memory_initial;
    }

    uint8_t read8(uint64_t addr)
    {
        auto it = memory.find(addr);
        if (it != memory.end())
        {
            return it->second.val;
        }
        else if (rng)
        {
            uint8_t v = dis(*rng);
            memory[addr] = mem_block_t{v, false};
            memory_initial[addr] = mem_block_t{v, false};
            return v;
        }
        else
        {
            // initial memory state provided, but program read uninitialized memory unexpectedly
            fprintf(stdout, "Error: unexpected read from uninitialized memory at address %p without initial state\n", (void *)addr);
            abort();
        }
    }

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
        auto it = memory.find(addr);
        if (it != memory.end())
        {
            it->second.val = val;
            it->second.written = true;
        }
        else
        {
            memory[addr] = mem_block_t{val, true};
        }
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

    bool operator==(const rand_memory_state &other)
    {
        return compare_memory_state(other);
    }
    bool operator!=(const rand_memory_state &other)
    {
        return !compare_memory_state(other);
    }
};

struct Memory
{
    rand_memory_state m;

    Memory(const rand_memory_state &initial_state)
        : m(initial_state)
    {
    }
};