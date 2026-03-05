#pragma once
// Workaround: LIEF defines DEBUG as a macro which conflicts with glog's DLOG
// macro expansion. Push/pop preserves any prior definition of DEBUG across the
// LIEF include, restoring it afterwards.  Supported by GCC, Clang, and MSVC.
#pragma push_macro("DEBUG")
#undef DEBUG
#include <LIEF/LIEF.hpp>
#pragma pop_macro("DEBUG")
