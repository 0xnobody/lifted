#pragma once

// Ugly hack to support Intellisense for KLEE
#ifdef __INTELLISENSE__
#include "../external/klee/include/klee/klee.h"
#else
#include <klee/klee.h>
#endif