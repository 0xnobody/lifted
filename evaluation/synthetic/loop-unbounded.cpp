#include "annotations.h"

extern "C"
int POLARIS_ANNOTATE test(int x)
{
    int sum = 0;
    for (int i = 0; i < x; i++) {
        sum += i;
    }
    return sum;
}