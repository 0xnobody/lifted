#include "annotations.h"

// Two independent functions in the same binary, used to verify that a single
// Lifter object can lift multiple entry points correctly and that the BB cache
// is populated across calls.

extern "C" int POLARIS_ANNOTATE func_a(int x)
{
    return x * x + 1;
}

extern "C" int POLARIS_ANNOTATE func_b(int x)
{
    if (x > 0)
        return x + 42;
    return -x + 42;
}
