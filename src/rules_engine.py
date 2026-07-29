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

VERSION = "1.4.1"

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
        self.bounty_spam = [(r["pattern"], r["id"]) for r in data.get("bounty_spam", [])]

    def _is_bounty_spam(self, cmd: str) -> tuple[bool, str]:
        for pat, reason in self.bounty_spam:
            m = re.search(pat, cmd, re.IGNORECASE)
            if m:
                return True, reason
        return False, ""

    def _is_safe_installer(self, cmd: str) -> bool:
        return any(re.search(pat, cmd, re.IGNORECASE) for pat, _ in self.safe_installers)

    def _is_safe_context(self, text: str) -> bool:
        # Educational / defensive / testing contexts where paste-jacking
        # instructions are not malicious.
        safe_markers = [
            r"\btest\s+(?:command|case|example|scenario|rule)\b",
            r"\bexample\s+(?:command|case|rule|test)\b",
            r"\btutorial\b",
            r"\bdocumentation\b",
            r"\bfor\s+(?:research|documentation|study|testing|education)\b",
            r"\bto\s+(?:understand|study|learn|defend|protect|research)\b",
            r"\bdefensive\s+(?:context|analysis|example|rule)\b",
            r"\bthe\s+rule\s+(?:for\s+)?['\"]",
            r"\bwe\s+(?:discussed|analyzed|audited|tested)\b",
            r"\bdo\s+not\s+(?:run|execute|copy|paste)\b",
            r"\bnever\s+(?:run|execute|copy|paste)\b",
            r"\bcopy\s+this\s+and\s+paste\s+it\s+into\s+(?:the\s+)?(?:your\s+)?(?:shell|terminal|console)\s+for\s+(?:the\s+)?(?:tutorial|documentation|example|test)",
            r"\bcopy\s+this\s+(?:command|code|script)\s+for\s+(?:the\s+)?(?:tutorial|documentation|example|test)",
        ]
        return any(re.search(pat, text, re.IGNORECASE) for pat in safe_markers)

    def _normalize(self, text: str) -> str:
        text = unicodedata.normalize("NFKC", text)
        # Strip ANSI escape sequences
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        # Strip other ANSI / OSC sequences
        text = re.sub(r"\x1b][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
        text = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]", "", text)
        # Resolve backspace sequences: char + backspace = delete previous char
        while "\x08" in text:
            text = re.sub(r"[^\x08]\x08", "", text)
            text = text.lstrip("\x08")
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

    def _run_blocked_checks(self, text: str) -> Optional[Verdict]:
        safe_context = self._is_safe_context(text)
        downgraded: Optional[Verdict] = None
        for pat, reason in self.blocked:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                if safe_context and ("paste" in reason or "copy_paste" in reason):
                    downgraded = Verdict(
                        "SUSPICIOUS",
                        1,
                        reasons=[reason, "explicit_safe_context_needs_review"],
                        matched=m.group(0),
                    )
                    continue
                if (reason.startswith("remote_fetch_to_shell") or reason in {"paste_jacking_15", "bash_c_remote_fetch", "sh_c_remote_fetch"}) and self._is_safe_installer(text):
                    downgraded = Verdict(
                        "SUSPICIOUS", 1,
                        reasons=[reason, "known_safe_installer_needs_confirmation"],
                        matched=m.group(0)
                    )
                    continue
                return Verdict("DANGEROUS", 2, reasons=[reason], matched=m.group(0))
        return downgraded

    def check(self, text: str) -> Verdict:
        text = self._normalize(text)
        if not text:
            return Verdict("SAFE", 0)

        spam, spam_reason = self._is_bounty_spam(text)
        if spam:
            return Verdict("DANGEROUS", 2, reasons=[f"bounty_spam: {spam_reason}"])

        result = self._run_blocked_checks(text)
        if result:
            return result

        decoded = self._try_decode_base64(text)
        if decoded:
            result = self._run_blocked_checks(decoded)
            if result:
                return Verdict(
                    "DANGEROUS", 2,
                    reasons=[f"{result.reasons[0]} (inside decoded payload)"],
                    matched=result.matched
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

        return Verdict("SAFE", 0)


class StreamChecker:
    """Stateful checker for streaming output that catches cross-chunk payloads."""

    def __init__(self, rules_path: Optional[Path] = None, lookback: int = 200):
        self.engine = RuleSet(rules_path)
        self.buffer: str = ""
        self.lookback = lookback

    def feed(self, chunk: str) -> Verdict:
        chunk = self.engine._normalize(chunk)
        if not chunk:
            return Verdict("SAFE", 0)

        # Check the chunk itself
        result = self.engine.check(chunk)
        if result.code >= 2:
            return result

        # Check combined with recent buffer (whitespace-collapsed)
        combined = self.engine._normalize(self.buffer + chunk)
        result = self.engine.check(combined)
        if result.code >= 2:
            return result

        combined_spaced = self.engine._normalize(self.buffer + " " + chunk)
        result = self.engine.check(combined_spaced)
        if result.code >= 2:
            return result

        # Update buffer: keep recent normalized text
        self.buffer = self.engine._normalize((self.buffer + " " + chunk)[-self.lookback:])

        return Verdict("SAFE", 0)

    def reset(self) -> None:
        self.buffer = ""


def check(text: str, rules_path: Optional[Path] = None) -> Verdict:
    engine = RuleSet(rules_path)
    return engine.check(text)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        v = check(" ".join(sys.argv[1:]))
        print(v.report())
        sys.exit(v.code)
