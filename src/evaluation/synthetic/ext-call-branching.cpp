#include <cstdio>
#include "annotations.h"

extern "C"
void POLARIS_ANNOTATE test(int x) 
{
    if (x > 0)
    {
        printf("Positive: %d\n", x);
    }
    else
    {
        printf("Non-positive: %d\n", x);
    }
}