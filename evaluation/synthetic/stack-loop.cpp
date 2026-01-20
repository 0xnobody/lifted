#include "annotations.h"

extern "C"
int POLARIS_ANNOTATE test(int x, int y)
{
    int arr[32];
    for (int i = 0; i < y; i++) {
        arr[i] = i + x;
    }
    return arr[x];
}