#include "annotations.h"

using fn = int(*)(int);

extern "C"
int POLARIS_ANNOTATE test(fn f, int x)
{
    return f(x) * 2;
}