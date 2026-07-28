#!/usr/bin/env python3
"""
LYTA Shield — terminal paste-jacking / social-engineering defense v1.0.0

Inspects shell commands before execution and blocks or confirms common
paste-jacking payloads.

Returns:
  0 = safe
  1 = suspicious (requires user confirmation)
  2 = dangerous (blocked)

License: MIT
Repository: https://github.com/Kubo-cmd/lyta-shield
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Tuple

from lyta_shield_rules import check, Verdict

VERSION = "1.0.0"


def scan_history(path: str) -> List[Tuple[int, str, Verdict]]:
    results = []
    p = Path(path)
    if not p.exists():
        return results
    for i, line in enumerate(p.read_text(errors="replace").splitlines(), start=1):
        v = check(line)
        if v.code != 0:
            results.append((i, line, v))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="LYTA Shield — terminal paste-jacking defense")
    parser.add_argument("--check", help="command string to classify")
    parser.add_argument("--batch", help="history file to scan")
    parser.add_argument("--json", action="store_true", help="output JSON")
    args = parser.parse_args()

    if args.check:
        v = check(args.check)
        if args.json:
            import json
            print(json.dumps({"action": v.action, "code": v.code, "reasons": v.reasons, "matched": v.matched}))
        else:
            print(v.report())
        return v.code

    if args.batch:
        results = scan_history(args.batch)
        if args.json:
            import json
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
