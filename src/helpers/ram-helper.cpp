#include <cstdint>
#include <cstring>

#include "types.hpp"

// Memory layout (0 length arrays treated as a simple pointer to unknown memory)

extern "C" uint8_t RAM[0];

// Implementation of the Remill memory access (read/write) intrinsics

HELPER uint8_t __remill_read_memory_8(Memory *m, addr_t a)
{
    uint8_t v = 0;
    std::memcpy(&v, (void *)&RAM[a], sizeof(v));
    return v;
}

HELPER uint16_t __remill_read_memory_16(Memory *m, addr_t a)
{
    uint16_t v = 0;
    std::memcpy(&v, (void *)&RAM[a], sizeof(v));
    return v;
}

HELPER uint32_t __remill_read_memory_32(Memory *m, addr_t a)
{
    uint32_t v = 0;
    std::memcpy(&v, (void *)&RAM[a], sizeof(v));
    return v;
}

HELPER uint64_t __remill_read_memory_64(Memory *m, addr_t a)
{
    uint64_t v = 0;
    std::memcpy(&v, (void *)&RAM[a], sizeof(v));
    return v;
}

HELPER Memory *__remill_write_memory_8(Memory *m, addr_t a, uint8_t v)
{
    std::memcpy((void *)&RAM[a], &v, sizeof(v));
    return m;
}

HELPER Memory *__remill_write_memory_16(Memory *m, addr_t a, uint16_t v)
{
    std::memcpy((void *)&RAM[a], &v, sizeof(v));
    return m;
}

HELPER Memory *__remill_write_memory_32(Memory *m, addr_t a, uint32_t v)
{
    std::memcpy((void *)&RAM[a], &v, sizeof(v));
    return m;
}

HELPER Memory *__remill_write_memory_64(Memory *m, addr_t a, uint64_t v)
{
    std::memcpy((void *)&RAM[a], &v, sizeof(v));
    return m;
}
