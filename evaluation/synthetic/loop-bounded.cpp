#include "annotations.h"

extern "C"
int POLARIS_ANNOTATE test(int x)
{
    for (int i = 0; i < 10; i++) {
        x += i;
    }
    return x;
}