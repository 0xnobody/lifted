#!/usr/bin/env python3
"""
extract_functions.py
--------------------
Extracts the functions defined within a single compilation unit and writes
a CSV with their final virtual addresses as recorded in the linked .so.

Strategy
--------
1. If --functions is given: use those names directly (skip nm on object).
2. Otherwise: run `nm --defined-only -f posix <object>` to get all T/t
   (text) symbols defined in that translation unit.  This reliably gives
   ONLY symbols from the .c/.cpp file - not stdlib, not inlined headers.
3. Run `nm --defined-only <so>` to build a name->VA map.
4. Intersect + write  func_name,addr  CSV (addr as 0x-prefixed hex).

When --object is absent (obfuscated variants compiled in one shot), step 2
is skipped and all T/t functions from the .so are used instead, with an
auxiliary-symbol filter applied to remove well-known CRT/linker symbols.
Use --no-filter-aux to disable that filter.

Usage
-----
  extract_functions.py --object foo.cpp.o --so libeval-foo.so --output foo.targets.csv
  extract_functions.py --so libeval-foo-polaris.so --output foo-polaris.targets.csv
  extract_functions.py --object foo.cpp.o --so lib.so --output out.csv \
                       --functions main helper_fn
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path


# -- Auxiliary / CRT symbol filter -------------------------------------------
# These symbols are injected by the compiler/linker toolchain into every shared
# library and have nothing to do with the source file being evaluated.
#
# Exact-name blocklist (stable across GCC/Clang on Linux x86-64):
_AUX_EXACT: frozenset[str] = frozenset({
    # CRT init/fini machinery
    "_init", "_fini", "_start",
    "deregister_tm_clones", "register_tm_clones",
    "frame_dummy",
    "__do_global_dtors_aux",
    "__libc_csu_init", "__libc_csu_fini",
    # PIE trampolines
    "_dl_relocate_static_pie",
    "call_weak_fn",
})

# Prefix blocklist - symbols starting with these are implementation-reserved
# and are never user-defined evaluation targets.
_AUX_PREFIXES: tuple[str, ...] = (
    "__",           # double-underscore -> reserved by C/C++ standard
    "_GLOBAL_",     # G++ global constructor helpers
)


def _is_auxiliary(name: str) -> bool:
    """Return True if the symbol looks like a CRT/linker-generated artifact."""
    if name in _AUX_EXACT:
        return True
    return any(name.startswith(p) for p in _AUX_PREFIXES)


# -- nm helpers ---------------------------------------------------------------

def _run_nm(path: Path, extra_flags: list[str] | None = None) -> list[str]:
    """Run nm on a file and return output lines, or [] on failure."""
    cmd = ["nm", "--defined-only", "-f", "posix"] + (extra_flags or []) + [str(path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as exc:
        print(f"[extract_functions] nm failed on {path}: {exc.stderr.strip()}", file=sys.stderr)
        return []


def _parse_nm_posix(lines: list[str], keep_types: str = "Tt") -> dict[str, int]:
    """
    Parse `nm -f posix` output into {name: value}.
    Posix format: <name> <type> <value> [<size>]
    We only keep symbols whose type char is in `keep_types`.
    """
    result: dict[str, int] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        name, sym_type, value_str = parts[0], parts[1], parts[2]
        if sym_type not in keep_types:
            continue
        try:
            result[name] = int(value_str, 16)
        except ValueError:
            continue
    return result


# -- demangle -----------------------------------------------------------------

def _demangle(name: str) -> str:
    """Try c++filt; fall back to the raw name on any error."""
    try:
        out = subprocess.run(
            ["c++filt", name], capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except Exception:
        return name


# -- main ---------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Extract per-TU function addresses into CSV")
    parser.add_argument("--object", metavar="OBJ", help="Object file (.o) for TU symbol detection")
    parser.add_argument("--so",     required=True, metavar="SO", help="Linked shared library (.so)")
    parser.add_argument("--output", required=True, metavar="CSV", help="Output CSV path")
    parser.add_argument("--functions", metavar="FN", nargs="+",
                        help="Explicit function names to include (overrides auto-detect)")
    parser.add_argument("--no-filter-aux", action="store_true",
                        help="Disable auxiliary/CRT symbol filtering "
                             "(only applies when --object is absent)")
    args = parser.parse_args()

    so_path  = Path(args.so)
    out_path = Path(args.output)

    if not so_path.exists():
        print(f"[extract_functions] ERROR: .so not found: {so_path}", file=sys.stderr)
        sys.exit(1)

    # -- Step 1: determine which names we care about --------------------------
    wanted: set[str] | None
    if args.functions:
        wanted = set(args.functions)
    elif args.object:
        obj_path = Path(args.object)
        if not obj_path.exists():
            print(f"[extract_functions] ERROR: object not found: {obj_path}", file=sys.stderr)
            sys.exit(1)
        obj_syms = _parse_nm_posix(_run_nm(obj_path), keep_types="Tt")
        wanted = set(obj_syms.keys())
    else:
        # No object file - will use all T/t symbols from the .so (with aux filter)
        wanted = None

    # -- Step 2: build name->VA map from the .so ------------------------------
    so_syms = _parse_nm_posix(_run_nm(so_path), keep_types="TtWw")

    # -- Step 3: filter + write -----------------------------------------------
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str]] = []
    if wanted is None:
        # All defined functions from the .so, minus known CRT artifacts
        for name, addr in sorted(so_syms.items()):
            if not args.no_filter_aux and _is_auxiliary(name):
                continue
            rows.append((name, hex(addr)))
    else:
        for name in sorted(wanted):
            if name in so_syms:
                rows.append((name, hex(so_syms[name])))
            else:
                print(f"[extract_functions] Warning: '{name}' not found in {so_path.name}",
                      file=sys.stderr)

    with out_path.open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["func_name", "addr"])
        writer.writerows(rows)

    print(f"[extract_functions] {len(rows)} function(s) written to {out_path}")


if __name__ == "__main__":
    main()
