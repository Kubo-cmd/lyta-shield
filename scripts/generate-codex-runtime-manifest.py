#!/usr/bin/env python3
"""Generate the exact local Codex Security runtime integrity manifest."""

from __future__ import annotations

import argparse
import importlib.util
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE_PATH = ROOT / "integrations" / "codex_security_bridge.py"
SPEC = importlib.util.spec_from_file_location("codex_security_bridge_manifest", BRIDGE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load Codex Security bridge")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT / "integrations" / "codex-security-runtime" / "node_modules",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.root.parent / (
        f"runtime-integrity-{platform.system().lower()}-{platform.machine().lower()}.json"
    )
    bridge.write_runtime_manifest(args.root, output)
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
