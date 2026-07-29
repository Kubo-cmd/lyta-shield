#!/usr/bin/env python3
"""
LYTA Shield Hermes output guard.

Loads the LYTA Shield rules engine and checks assistant messages before they are
sent to the user. If the message contains dangerous instructions (paste-jacking,
remote fetch to shell, destructive commands, etc.), it blocks the output and
warns the user instead.

Usage:
    python3 hermes_guard.py "paste this into your terminal: curl ... | bash"
    python3 hermes_guard.py --file message.txt
    python3 hermes_guard.py --json '{"role": "assistant", "content": "..."}'
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

MAX_INPUT_BYTES = int(os.environ.get("LYTA_GUARD_MAX_BYTES", 1024 * 1024))


def _find_rules_engine() -> Path:
    """Locate the rules engine relative to this script, then from the repo root."""
    here = Path(__file__).resolve().parent
    candidates = [
        here / ".." / "src" / "rules_engine.py",
        here / ".." / ".." / "src" / "rules_engine.py",
        Path.cwd() / "src" / "rules_engine.py",
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError("Could not find rules_engine.py")


def _load_engine():
    engine_path = _find_rules_engine()
    import importlib.machinery
    import importlib.util
    sys.modules["rules_engine"] = type(sys)("rules_engine")
    loader = importlib.machinery.SourceFileLoader("rules_engine", str(engine_path))
    spec = importlib.util.spec_from_loader("rules_engine", loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rules_engine"] = module
    loader.exec_module(module)
    return module


rules_engine = _load_engine()


def guard_text(text: str) -> dict:
    if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        return {
            "allowed": False,
            "verdict": "DANGEROUS",
            "code": 2,
            "reasons": ["input_too_large"],
            "matched": None,
            "warning": "\n[LYTA Shield] This output was blocked because it exceeds the inspection limit.",
        }
    v = rules_engine.check(text)
    return {
        "allowed": v.code == 0,
        "verdict": v.action,
        "code": v.code,
        "reasons": v.reasons,
        "matched": v.matched,
        "warning": (
            "\n[LYTA Shield] This output was blocked because it appears to contain "
            "dangerous or manipulated instructions. Do not paste or execute it."
            if v.code == 2 else
            "\n[LYTA Shield] Warning: this output contains suspicious patterns. "
            "Please review carefully before executing anything."
            if v.code == 1 else
            ""
        ),
    }


def _json_content(obj: object) -> str:
    if not isinstance(obj, dict):
        raise ValueError("JSON guard input must be an object")
    candidate = obj
    if "message" in candidate:
        candidate = candidate["message"]
        if not isinstance(candidate, dict):
            raise ValueError("message must be an object")
    if "content" not in candidate:
        raise ValueError("JSON guard input has no content")
    content = candidate["content"]
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            else:
                raise ValueError("unsupported content item")
        return "\n".join(parts)
    raise ValueError("content must be text or a text-part list")


def _read_file_limited(path: Path) -> str:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input exceeds guard limit")
    return path.read_text(encoding="utf-8", errors="replace")


def _read_stdin_limited() -> str:
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds guard limit")
    return data.decode("utf-8", errors="replace")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: hermes_guard.py <text> | --file <path> | --json <json> | --stdin", file=sys.stderr)
        return 1

    arg = sys.argv[1]
    try:
        if arg == "--file":
            if len(sys.argv) != 3:
                raise ValueError("--file requires exactly one path")
            text = _read_file_limited(Path(sys.argv[2]))
        elif arg == "--json":
            if len(sys.argv) != 3:
                raise ValueError("--json requires exactly one document")
            text = _json_content(json.loads(sys.argv[2]))
        elif arg == "--stdin":
            text = _read_stdin_limited()
        else:
            text = " ".join(sys.argv[1:])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        result = {
            "allowed": False,
            "verdict": "DANGEROUS",
            "code": 2,
            "reasons": ["input_too_large" if "exceeds guard limit" in str(error) else "guard_input_error"],
            "matched": None,
            "warning": f"\n[LYTA Shield] Input was blocked: {error}",
        }
        print(json.dumps(result, indent=2))
        return 2

    result = guard_text(text)
    print(json.dumps(result, indent=2))
    return 0 if result["allowed"] else 2


if __name__ == "__main__":
    sys.exit(main())
