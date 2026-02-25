#pragma once

#include "verifier_context.hpp"

#include <setjmp.h>

using fn_is_fallthrough_edge = bool (*)(uint64_t from_rva, uint64_t to_rva, void *executor_data);

struct jit_executor_context_t
{
    verifier_context_t *verifier_context;

    jmp_buf exit_jmp;

    fn_is_fallthrough_edge is_fallthrough_edge;
    uint64_t last_bb_rva = -1;

    void *executor_data;
};