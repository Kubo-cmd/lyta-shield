#!/usr/bin/env python3
"""
LYTA Shield Rules Engine
JSON-driven, modular, shared backend for terminal, browser, and AI chat guards.
"""
from __future__ import annotations

import base64
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

VERSION = "1.1.0"

RULES_PATH = Path(__file__).with_name("rules.json")


@dataclass
class Verdict:
    action: str
    code: int
    reasons: List[str] = field(default_factory=list)
    matched: Optional[str] = None

    def report(self) -> str:
        lines = [f"[LYTA Shield v{VERSION}] Verdict: {self.action}"]
        if self.reasons:
            lines.append("  Reasons:")
            for r in self.reasons:
                lines.append(f"    - {r}")
        if self.matched:
            lines.append(f"  Matched: {self.matched}")
        return "\n".join(lines)


class RuleSet:
    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path or RULES_PATH
        self._load()

    def _load(self) -> None:
        with self.rules_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self.version = data.get("version", VERSION)
        self.blocked = [(r["pattern"], r["id"]) for r in data.get("blocked", [])]
        self.suspicious = [(r["pattern"], r["id"]) for r in data.get("suspicious", [])]
        self.safe_installers = [(r["pattern"], r["id"]) for r in data.get("safe_installers", [])]

    def _is_safe_installer(self, cmd: str) -> bool:
        return any(re.search(pat, cmd, re.IGNORECASE) for pat, _ in self.safe_installers)

    def _normalize(self, text: str) -> str:
        text = unicodedata.normalize("NFKC", text)
        text = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _try_decode_base64(self, text: str) -> str:
        m = re.search(r"['\"]([A-Za-z0-9+/=\s]{20,})['\"]\s*\|\s*base64", text)
        if not m:
            return ""
        blob = re.sub(r"\s+", "", m.group(1))
        try:
            return base64.b64decode(blob).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def check(self, text: str) -> Verdict:
        text = self._normalize(text)
        if not text:
            return Verdict("SAFE", 0)

        for pat, reason in self.blocked:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                if reason == "remote_fetch_to_shell" and self._is_safe_installer(text):
                    return Verdict(
                        "SUSPICIOUS", 1,
                        reasons=[reason, "known_safe_installer_needs_confirmation"],
                        matched=m.group(0)
                    )
                return Verdict("DANGEROUS", 2, reasons=[reason], matched=m.group(0))

        decoded = self._try_decode_base64(text)
        if decoded:
            for pat, reason in self.blocked:
                if re.search(pat, decoded, re.IGNORECASE):
                    return Verdict(
                        "DANGEROUS", 2,
                        reasons=[f"{reason} (inside decoded payload)"],
                        matched=decoded[:80]
                    )
            if re.search(r"\b(curl|wget|bash|sh|exec|eval)\b", decoded, re.IGNORECASE):
                return Verdict(
                    "DANGEROUS", 2,
                    reasons=["decoded_base64_contains_shell_commands"],
                    matched=decoded[:80]
                )

        reasons = []
        for pat, reason in self.suspicious:
            if re.search(pat, text, re.IGNORECASE):
                reasons.append(reason)
        if reasons:
            return Verdict("SUSPICIOUS", 1, reasons=reasons)

        if self._is_safe_installer(text):
            return Verdict("SAFE", 0, reasons=["known_safe_installer"])

        return Verdict("SAFE", 0)


def check(text: str, rules_path: Optional[Path] = None) -> Verdict:
    engine = RuleSet(rules_path)
    return engine.check(text)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        v = check(" ".join(sys.argv[1:]))
        print(v.report())
        sys.exit(v.code)
