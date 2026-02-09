/*
  Original author: https://github.com/fvrmatteo
*/

#include <cstdint>
#include <cstring>

#include "types.hpp"
#include "standard-intrinsics.hpp"

HELPER Memory *__lifted_ext_call(State *__restrict__, addr_t addr, Memory *);

HELPER Memory *__lifted_issue_ext_call(State *__restrict__ s, addr_t addr, Memory *m)
{
    __lifted_ext_call(s, addr, m);
    s->gpr.rip.qword = __remill_read_memory_64(m, s->gpr.rsp.qword);
    s->gpr.rsp.qword += 8;
    return m;
}