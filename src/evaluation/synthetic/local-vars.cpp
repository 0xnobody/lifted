#include "annotations.h"

extern "C"
int POLARIS_ANNOTATE test(int x, int y, int z, int* p)
{
    char barr[5];
    int iarr[8];

    barr[0] = static_cast<char>(p[x]);
    barr[1] = static_cast<char>(p[y]);
    barr[2] = static_cast<char>(p[z]);
    barr[3] = barr[0] + barr[1];
    barr[4] = barr[1] + barr[2];

    iarr[0] = static_cast<int>(barr[0]);
    iarr[1] = static_cast<int>(barr[1]);
    iarr[2] = static_cast<int>(barr[2]);
    iarr[3] = static_cast<int>(barr[3]);
    iarr[4] = static_cast<int>(barr[4]);
    iarr[5] = iarr[0] + iarr[1];
    iarr[6] = iarr[2] + iarr[3];
    iarr[7] = iarr[4] + iarr[5] + iarr[6];

    return barr[x] + iarr[y] + iarr[z];
}