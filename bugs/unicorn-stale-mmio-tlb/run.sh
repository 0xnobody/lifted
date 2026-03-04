#!/usr/bin/env bash
# run.sh — compile and run the stale-TLB-MMIO POC against the project's
#          local Unicorn build.  No project integration required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

UNICORN_INSTALL="$REPO_ROOT/build/unicorn-install"
UNICORN_INCLUDE="$UNICORN_INSTALL/include"
UNICORN_LIB="$UNICORN_INSTALL/lib"
OUT="$SCRIPT_DIR/poc"

# ── sanity checks ─────────────────────────────────────────────────────────────
if [[ ! -f "$UNICORN_INSTALL/lib/libunicorn.so" ]]; then
    echo "ERROR: Unicorn not built yet." >&2
    echo "       Build the project first so that $UNICORN_INSTALL is populated." >&2
    exit 2
fi

# ── compile ───────────────────────────────────────────────────────────────────
echo "Compiling $SCRIPT_DIR/poc.c ..."
cc -std=c11 -Wall -Wextra -g -O0 \
    -I"$UNICORN_INCLUDE" \
    -L"$UNICORN_LIB" \
    "$SCRIPT_DIR/poc.c" \
    -o "$OUT" \
    -lunicorn

echo "Compiled → $OUT"
echo

# ── run ───────────────────────────────────────────────────────────────────────
LD_LIBRARY_PATH="$UNICORN_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$OUT"
