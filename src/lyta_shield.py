#!/usr/bin/env python3
"""
LYTA Shield — Terminal guard v1.5.3

Inspects shell commands before execution and blocks or confirms common
paste-jacking payloads.

Returns:
  0 = safe
  1 = suspicious (requires user confirmation)
  2 = dangerous (blocked)

License: MIT
Repository: configured Git origin
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Tuple

from rules_engine import Verdict, check

VERSION = "1.5.3"


def scan_history(path: str, rules_path: Path | None = None) -> List[Tuple[int, str, Verdict]]:
    results = []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"history file does not exist: {p}")
    if p.is_symlink() or not p.is_file():
        raise ValueError(f"history path must be a regular file: {p}")
    for i, line in enumerate(p.read_text(errors="replace").splitlines(), start=1):
        v = check(line, rules_path=rules_path)
        if v.code != 0:
            results.append((i, line, v))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="LYTA Shield — terminal paste-jacking defense")
    parser.add_argument("--check", help="command string to classify")
    parser.add_argument("--batch", help="history file to scan")
    parser.add_argument("--rules", help="path to rules.json")
    parser.add_argument("--json", action="store_true", help="output JSON")
    args = parser.parse_args()

    rules_path = Path(args.rules) if args.rules else None
    if args.check:
        v = check(args.check, rules_path=rules_path)
        if args.json:
            print(json.dumps({"action": v.action, "code": v.code, "reasons": v.reasons, "matched": v.matched}))
        else:
            print(v.report())
        return v.code

    if args.batch:
        try:
            results = scan_history(args.batch, rules_path=rules_path)
        except (OSError, ValueError) as error:
            print(f"[LYTA Shield] Batch scan failed: {error}", file=sys.stderr)
            return 2
        if args.json:
            out = [{"line": ln, "command": cmd, "action": v.action, "reasons": v.reasons, "matched": v.matched} for ln, cmd, v in results]
            print(json.dumps(out))
        else:
            print(f"[LYTA Shield] Scanned {args.batch}: {len(results)} risky line(s)")
            for ln, cmd, v in results:
                print(f"  line {ln}: {v.action} -> {v.reasons}")
                print(f"    cmd: {cmd[:120]}")
        return 0 if not results else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
