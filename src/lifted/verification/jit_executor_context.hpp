#pragma once

#include "verifier_context.hpp"

#include <setjmp.h>

struct jit_executor_context_t
{
    verifier_context_t *verifier_context;

    jmp_buf exit_jmp;

    uint64_t last_bb_rva = uint64_t(-1);
};