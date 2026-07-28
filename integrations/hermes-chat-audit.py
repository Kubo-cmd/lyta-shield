#!/usr/bin/env python3
"""
Audit a saved Hermes chat log with LYTA Shield.

Reads a JSON/JSONL/txt file where each line is a JSON object with role/content keys,
like:
    {"role":"assistant","content":"..."}

Example:
    python3 hermes-chat-audit.py hermes-session.jsonl
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "integrations" / "hermes_guard.py"


def parse_records(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix in (".jsonl", ".txt") or "\n" in text.strip():
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
    else:
        data = json.loads(text)
        if isinstance(data, list):
            yield from data
        else:
            yield data


def main():
    parser = argparse.ArgumentParser(description="Audit Hermes chat logs with LYTA Shield")
    parser.add_argument("file", help="Chat log file (jsonl/txt/json)")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 1

    results = {"safe": 0, "suspicious": 0, "dangerous": 0}
    for msg in parse_records(path):
        if msg.get("role") != "assistant":
            continue
        res = subprocess.run(
            [sys.executable, str(GUARD), "--json", json.dumps(msg)],
            capture_output=True, text=True
        )
        try:
            verdict = json.loads(res.stdout)
        except json.JSONDecodeError:
            continue
        code = verdict.get("code", -1)
        if code == 0:
            results["safe"] += 1
        elif code == 1:
            results["suspicious"] += 1
            print(f"[SUSPICIOUS] {', '.join(verdict.get('reasons', []))}")
            print(f"  {msg.get('content', '')[:200]!r}")
            print()
        else:
            results["dangerous"] += 1
            print(f"[DANGEROUS] {', '.join(verdict.get('reasons', []))}")
            print(f"  {msg.get('content', '')[:200]!r}")
            print()

    print(f"Audit complete: {results}")
    return 0


if __name__ == "__main__":
    import subprocess
    raise SystemExit(main())
