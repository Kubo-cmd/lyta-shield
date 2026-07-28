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
import sys
from pathlib import Path

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
    import importlib.util
    import importlib.machinery
    sys.modules["rules_engine"] = type(sys)("rules_engine")
    loader = importlib.machinery.SourceFileLoader("rules_engine", str(engine_path))
    spec = importlib.util.spec_from_loader("rules_engine", loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rules_engine"] = module
    loader.exec_module(module)
    return module


rules_engine = _load_engine()


def guard_text(text: str) -> dict:
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


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: hermes_guard.py <text> | --file <path> | --json <json>", file=sys.stderr)
        return 1

    arg = sys.argv[1]
    if arg == "--file":
        text = Path(sys.argv[2]).read_text(encoding="utf-8")
    elif arg == "--json":
        obj = json.loads(sys.argv[2])
        text = obj.get("content", "") if isinstance(obj, dict) else obj
    else:
        text = " ".join(sys.argv[1:])

    result = guard_text(text)
    print(json.dumps(result, indent=2))
    return 0 if result["allowed"] else 2


if __name__ == "__main__":
    sys.exit(main())
