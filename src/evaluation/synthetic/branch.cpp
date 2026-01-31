#include "annotations.h"

extern "C"
int POLARIS_ANNOTATE test(int x) 
{
    if (x > 0) {
        x += 10;
    } else {
        x -= 10;
    }

    return x;
}