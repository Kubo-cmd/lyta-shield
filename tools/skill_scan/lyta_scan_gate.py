#!/usr/bin/env python3
"""Live pre-write gate for skill materialization (ORACLE item, 2026-07-31).

Turns lyta_skill_scan from a proven-on-synthetic audit into the actual screen
every new skill passes through BEFORE its files land in ~/.hermes/skills/.

Two usage modes:

  1. As a module (preferred by skill authoring code):

       from lyta_scan_gate import gate_skill_write, SkillGateError
       try:
           gate_skill_write(skill_name, {
               "SKILL.md": md_text,
               "scripts/run.sh": sh_text,
           })
       except SkillGateError as e:
           # do NOT write — surface e.report to the human
           raise

  2. As a CLI over an already-staged directory (fails closed on BLOCK):

       python3 lyta_scan_gate.py /path/to/staged/skill_dir
       exit 0 = CLEAN or REVIEW (allowed, REVIEW is surfaced), 2 = BLOCK, 3 = error

Design contract (fail-closed):
  * If the scanner itself cannot import/run, the gate REFUSES the write.
  * BLOCK verdict  -> refuse (SkillGateError / exit 2).
  * REVIEW verdict -> allow but REPORT (the human sees what surfaced).
  * CLEAN verdict  -> allow silently.

This module never writes skill files itself; it only screens the intended
content and lets the caller decide. The caller MUST NOT proceed on SkillGateError.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path.home() / ".hermes" / "lyta_core"))
import lyta_skill_scan as scan  # noqa: E402


class SkillGateError(RuntimeError):
    """Raised when a skill write is refused by the gate."""

    def __init__(self, skill: str, report: dict):
        self.skill = skill
        self.report = report
        blocked = [f for f in report.get("findings", []) if f["severity"] == "BLOCK"]
        lines = "\n".join(f"  - {f['file']}:{f['line']} {f['risk']} :: {f['context'][:60]}" for f in blocked[:20])
        super().__init__(
            f"SKILL WRITE REFUSED: '{skill}' failed the pre-write scan "
            f"({len(blocked)} blocking finding(s)):\n{lines}"
        )


def _scan_content_map(files: dict[str, str]) -> dict:
    """Materialize {relpath: content} into a temp dir and scan it.

    Returns the scanner's report dict for the temp skill dir.
    """
    tmp = Path(tempfile.mkdtemp(prefix="lyta-gate-"))
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    # scan_skill_dir expects a directory containing the files; scan as one skill.
    return scan.scan_skill_dir(tmp)


def gate_skill_write(skill_name: str, files: dict[str, str]) -> dict:
    """Screen intended skill files BEFORE they are written to disk.

    Args:
        skill_name: human label for the skill (used in errors/report).
        files:      {relative_path: file_content} for every file the skill will write.

    Returns:
        The scanner report (verdict CLEAN or REVIEW) when the write is allowed.

    Raises:
        SkillGateError: when the verdict is BLOCK, or the scanner fail-closed.
    """
    if not scan._IMPORT_OK:
        raise SkillGateError(skill_name, {
            "skill": skill_name, "verdict": "BLOCK", "findings": [],
            "error": "scanner failed to import patterns (fail-closed)",
        })
    report = _scan_content_map(files)
    report["skill"] = skill_name
    if report["verdict"] == "BLOCK":
        raise SkillGateError(skill_name, report)
    return report


def gate_skill_dir(skill_dir: str | Path) -> dict:
    """Screen an already-staged directory. Same contract as gate_skill_write."""
    skill_dir = Path(skill_dir)
    if not scan._IMPORT_OK:
        raise SkillGateError(str(skill_dir), {
            "skill": str(skill_dir), "verdict": "BLOCK", "findings": [],
            "error": "scanner failed to import patterns (fail-closed)",
        })
    report = scan.scan_skill_dir(skill_dir)
    if report["verdict"] == "BLOCK":
        raise SkillGateError(skill_dir.name, report)
    return report


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: lyta_scan_gate.py <staged_skill_dir>", file=sys.stderr)
        return 3
    try:
        report = gate_skill_dir(argv[1])
    except SkillGateError as e:
        print(json.dumps({"allowed": False, "reason": str(e)}, indent=2))
        return 2
    allowed = report["verdict"] in ("CLEAN", "REVIEW")
    print(json.dumps({"allowed": allowed, "verdict": report["verdict"],
                      "findings": report["findings"]}, indent=2))
    return 0 if allowed else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
