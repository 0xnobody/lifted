#include <cstdio>
#include "annotations.h"

extern "C" void anonymous(int, int, int, int, int, int, int, int);

extern "C" int POLARIS_ANNOTATE test(int x)
{
    anonymous(x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7);

    return x;
}