#!/usr/bin/env python3
"""
generate_suite_csv.py
─────────────────────
Assembles the suite-level CSV that lists every binary (plain + obfuscated)
belonging to an evaluation suite.

Output format
─────────────
  so_path,targets_csv_path
  /abs/path/libeval-foo.so,/abs/path/foo.targets.csv
  /abs/path/libeval-foo-polaris.so,/abs/path/foo-polaris.targets.csv
  ...

Entries are passed as  --entry <so_path>:::<csv_path>
The  :::  separator was chosen to be safe against spaces / colons in
absolute paths on unusual systems.

Usage
─────
  generate_suite_csv.py --output tum-eval.targets.csv \
      --entry /build/libeval-cat.so:::/build/cat.targets.csv \
      --entry /build/libeval-wc.so:::/build/wc.targets.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate evaluation suite CSV")
    parser.add_argument("--output", required=True, metavar="CSV",
                        help="Output suite CSV path")
    parser.add_argument("--entry", metavar="SO:::CSV", action="append", dest="entries",
                        help="Entry in format so_path:::targets_csv_path (repeat for each binary)")
    args = parser.parse_args()

    if not args.entries:
        print("[generate_suite_csv] Warning: no entries provided – writing empty suite CSV", file=sys.stderr)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str]] = []
    for raw in (args.entries or []):
        sep = ":::"
        if sep not in raw:
            print(f"[generate_suite_csv] ERROR: entry missing ':::' separator: {raw!r}", file=sys.stderr)
            sys.exit(1)
        so_path, csv_path = raw.split(sep, 1)
        rows.append((so_path.strip(), csv_path.strip()))

    with out_path.open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["so_path", "targets_csv_path"])
        writer.writerows(rows)

    print(f"[generate_suite_csv] Suite CSV written: {out_path} ({len(rows)} entries)")


if __name__ == "__main__":
    main()
