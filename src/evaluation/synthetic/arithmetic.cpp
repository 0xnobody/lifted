#include "annotations.h"

extern "C"
int POLARIS_ANNOTATE test(int x) 
{
    return (x * 2) | 7772 & x + 442;
}