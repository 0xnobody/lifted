#!/usr/bin/env python3
"""
generate_suite_csv.py
─────────────────────
Assembles the suite-level CSV that lists every binary (plain + obfuscated)
belonging to an evaluation suite.

Output format
─────────────
  so_path,targets_csv_path,obfuscator
  /abs/path/libeval-foo.so,/abs/path/foo.targets.csv,
  /abs/path/libeval-foo-polaris.so,/abs/path/foo-polaris.targets.csv,polaris
  ...

The obfuscator field is empty for plain (non-obfuscated) binaries.

Entries are passed as  --entry <so_path>:::<csv_path>:::<obfuscator>
The  :::  separator was chosen to be safe against spaces / colons in
absolute paths on unusual systems.

Usage
─────
  generate_suite_csv.py --output tum-eval.targets.csv \
      --entry /build/libeval-foo.so:::/build/foo.targets.csv::: \
      --entry /build/libeval-foo-polaris.so:::/build/foo-polaris.targets.csv:::polaris
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
    parser.add_argument("--entry", metavar="SO:::CSV:::OBF", action="append", dest="entries",
                        help="Entry in format so_path:::targets_csv_path:::obfuscator (obfuscator may be empty; repeat for each binary)")
    args = parser.parse_args()

    if not args.entries:
        print("[generate_suite_csv] Warning: no entries provided – writing empty suite CSV", file=sys.stderr)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str, str]] = []
    for raw in (args.entries or []):
        sep = ":::"
        if sep not in raw:
            print(f"[generate_suite_csv] ERROR: entry missing ':::' separator: {raw!r}", file=sys.stderr)
            sys.exit(1)
        parts = raw.split(sep, 2)
        so_path = parts[0].strip()
        csv_path = parts[1].strip()
        obfuscator = parts[2].strip() if len(parts) == 3 else ""
        rows.append((so_path, csv_path, obfuscator))

    with out_path.open("w", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["so_path", "targets_csv_path", "obfuscator"])
        writer.writerows(rows)

    print(f"[generate_suite_csv] Suite CSV written: {out_path} ({len(rows)} entries)")


if __name__ == "__main__":
    main()
