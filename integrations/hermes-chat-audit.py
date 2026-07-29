#!/usr/bin/env python3
"""Audit assistant output in JSON/JSONL chat exports with bounded parsing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator

from hermes_guard import guard_text

MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 8
ASSISTANT_ROLES = {"assistant", "model", "agent"}


def text_fragments(value: Any, depth: int = 0) -> Iterator[str]:
    if depth > MAX_DEPTH:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from text_fragments(item, depth + 1)
    elif isinstance(value, dict):
        for key in ("text", "content", "output_text", "message"):
            if key in value:
                yield from text_fragments(value[key], depth + 1)


def assistant_content(record: Any) -> str:
    if not isinstance(record, dict):
        return ""
    message = record.get("message")
    role = record.get("role")
    if isinstance(message, dict):
        role = message.get("role", role)
        content = message.get("content", record.get("content", ""))
    else:
        content = record.get("content", record.get("output", ""))
    if str(role).lower() not in ASSISTANT_ROLES:
        return ""
    return "\n".join(fragment for fragment in text_fragments(content) if fragment)


def records(path: Path) -> Iterator[tuple[int, Any]]:
    with path.open("rb") as handle:
        prefix = handle.read(4096).lstrip()[:1]
        handle.seek(0)
        if prefix == b"[":
            raw = handle.read(MAX_LINE_BYTES + 1)
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError("chat export exceeds bounded JSON size; use JSONL")
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            values = parsed if isinstance(parsed, list) else [parsed]
            for index, value in enumerate(values, 1):
                yield index, value
            return
        for line_number, raw in enumerate(handle, 1):
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"line {line_number} exceeds size limit")
            if raw.strip():
                yield line_number, json.loads(raw.decode("utf-8", errors="replace"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    highest = 0
    scanned = 0
    try:
        for position, record in records(args.path):
            content = assistant_content(record)
            if not content:
                continue
            scanned += 1
            result = guard_text(content)
            highest = max(highest, int(result["code"]))
            if result["code"]:
                print(f"[{result['verdict']}] record {position}: {', '.join(result['reasons'])}")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[FAIL] chat audit: {error}", file=sys.stderr)
        return 2
    print(f"Audited {scanned} assistant messages")
    return highest


if __name__ == "__main__":
    raise SystemExit(main())
