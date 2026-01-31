#include <cstdio>
#include "annotations.h"

extern "C"
void POLARIS_ANNOTATE test(int x) 
{
    printf("Positive: %d\n", x);
}