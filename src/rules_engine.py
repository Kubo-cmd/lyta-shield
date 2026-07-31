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

VERSION = "1.5.3"

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

        if not isinstance(data, dict):
            raise ValueError("rules document must be a JSON object")
        required = ("blocked", "suspicious", "safe_installers", "bounty_spam")
        missing = [name for name in required if name not in data]
        if missing:
            raise ValueError(f"rules document missing required sections: {', '.join(missing)}")
        for name in required:
            entries = data[name]
            if not isinstance(entries, list) or not entries:
                raise ValueError(f"rules section must be a non-empty list: {name}")
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError(f"invalid rule entry: {name}[{index}]")
                fields = set(entry)
                if not {"pattern", "id"}.issubset(fields) or not fields.issubset({"pattern", "id", "description"}):
                    raise ValueError(f"invalid rule entry: {name}[{index}]")
                if not all(isinstance(entry[key], str) and entry[key].strip() for key in ("pattern", "id")):
                    raise ValueError(f"empty rule field: {name}[{index}]")
                if "description" in entry and not isinstance(entry["description"], str):
                    raise ValueError(f"invalid rule description: {name}[{index}]")
                try:
                    re.compile(entry["pattern"], re.IGNORECASE)
                except re.error as error:
                    raise ValueError(f"invalid regex in {name}[{index}]: {error}") from error

        self.version = data.get("version", VERSION)
        self.blocked = [(r["pattern"], r["id"]) for r in data["blocked"]]
        self.suspicious = [(r["pattern"], r["id"]) for r in data["suspicious"]]
        self.safe_installers = [(r["pattern"], r["id"]) for r in data["safe_installers"]]
        self.bounty_spam = [(r["pattern"], r["id"]) for r in data["bounty_spam"]]

    def _is_bounty_spam(self, cmd: str) -> tuple[bool, str]:
        for pat, reason in self.bounty_spam:
            m = re.search(pat, cmd, re.IGNORECASE)
            if m:
                return True, reason
        return False, ""

    def _is_safe_installer(self, matched_pipeline: str) -> bool:
        urls = re.findall(r"https://[^\s'\"|;]+", matched_pipeline, re.IGNORECASE)
        return len(urls) == 1 and any(
            re.fullmatch(pattern, url.rstrip(")],"), re.IGNORECASE)
            for url in urls
            for pattern, _ in self.safe_installers
        )

    @staticmethod
    def _local_clause(text: str, start: int, end: int) -> str:
        left = max(text.rfind(marker, 0, start) for marker in ".!?\n") + 1
        boundaries = [position for marker in ".!?\n" if (position := text.find(marker, end)) >= 0]
        right = min(boundaries) if boundaries else len(text)
        return text[left:right]

    def _is_safe_context(self, text: str, start: int, end: int) -> bool:
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
        local_context = self._local_clause(text, start, end)
        return any(re.search(pat, local_context, re.IGNORECASE) for pat in safe_markers)

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

    @staticmethod
    def _canonicalize_shell(text: str) -> str:
        """Collapse common shell-equivalent spellings before policy checks."""
        text = re.sub(r"\\(?=[A-Za-z0-9_./-])", "", text)
        text = re.sub(r"(?<![\w/])/(?:usr/)?bin/((?:ba|z|da)?sh)\b", r"\1", text, flags=re.IGNORECASE)
        text = re.sub(r"\|\s*command\s+(?=(?:ba|z|da)?sh\b)", "| ", text, flags=re.IGNORECASE)
        text = re.sub(r"\brm\s+--recursive\b", "rm -r", text, flags=re.IGNORECASE)
        text = re.sub(r"\brm\s+(-[^\s]+)\s+--force\b", r"rm \1 -f", text, flags=re.IGNORECASE)

        def merge_rm_flags(match: re.Match[str]) -> str:
            flags = "".join(re.findall(r"[rf]", match.group(1), flags=re.IGNORECASE)).lower()
            ordered = "".join(flag for flag in "rf" if flag in flags)
            return f"rm -{ordered} " if ordered else match.group(0)

        return re.sub(r"\brm\s+((?:-[rf]+\s+){2,})", merge_rm_flags, text, flags=re.IGNORECASE)

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
        downgraded: Optional[Verdict] = None
        for pat, reason in self.blocked:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                if self._is_safe_context(text, m.start(), m.end()) and ("paste" in reason or "copy_paste" in reason):
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
        text = self._canonicalize_shell(self._normalize(text))
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

        combined = self.engine._normalize(self.buffer + chunk)
        combined_spaced = self.engine._normalize(self.buffer + " " + chunk)
        candidates = (
            self.engine.check(chunk),
            self.engine.check(combined),
            self.engine.check(combined_spaced),
        )
        self.buffer = self.engine._normalize((self.buffer + " " + chunk)[-self.lookback:])
        return max(candidates, key=lambda verdict: verdict.code)

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
