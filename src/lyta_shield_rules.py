#!/usr/bin/env python3
"""
LYTA Shield Rules Engine
Shared backend for terminal, browser, and AI chat guards.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

VERSION = "1.0.0"

BLOCKED_PATTERNS: List[Tuple[str, str]] = [
    (r"(echo\s+['\"]?[A-Za-z0-9+/=\s]{40,}['\"]?\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(\/bin\/)?(ba)?sh)\b", "base64_decode_to_shell"),
    (r"(base64\s+(-d|--decode)\s*.*?\|\s*(\/bin\/)?(ba)?sh)\b", "base64_decode_to_shell"),
    (r"(python[23]?(?:\s+-c)?\s*['\"].*?(?:base64|exec|eval|__import__)\s*.*?['\"])", "python_obfuscated_exec"),
    (r"(perl\s+-e\s*['\"].*?(?:system|exec|eval)\s*.*?['\"])", "perl_obfuscated_exec"),
    (r"(ruby\s+-e\s*['\"].*?(?:exec|eval|system)\s*.*?['\"])", "ruby_obfuscated_exec"),
    (r"(\bnode\s+-e\s*['\"].*?(?:exec|eval)\s*.*?['\"])", "node_obfuscated_exec"),
    (r"\b(curl|wget|fetch)\b.*?\|\s*(ba)?sh\b", "remote_fetch_to_shell"),
    (r"\b(curl|wget|fetch)\b.*?(?:\s+\|\s+(sudo\s+)?(ba)?sh|(?:bash|sh)\s+-c)", "remote_fetch_to_shell"),
    (r"\b(curl|wget|fetch)\b.*?\s+>\s+/tmp/\w+\s*\&\&\s*chmod\s*\+x\s+/tmp/\w+\s*(?:&&|;|\|\|)\s*\S*/tmp/\w+", "remote_fetch_chmod_execute"),
    (r"(paste\s+this\s+(?:command|code)\s+(?:into|in)\s+(?:your\s+)?(?:terminal|shell|console))\b", "paste_jacking_instruction"),
    (r"(copy\s+this\s+(?:command|code|script|text)\s+(?:and\s+)?(?:paste|run|execute)\s+it)\b", "paste_jacking_instruction"),
    (r"(copy\s+(?:and\s+)?paste\s+(?:this\s+)?(?:command|code|script|text))\b", "paste_jacking_instruction"),
    (r"(copy\s+(?:the\s+following\s+)?(?:command|code|script|text)\s+(?:and\s+)?paste\s+(?:it\s+)?(?:into|in|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt))\b", "paste_jacking_instruction"),
    (r"(paste\s+(?:the\s+following\s+)?(?:command|code|script|text)\s+(?:into|in|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt))\b", "paste_jacking_instruction"),
    (r"(copy\s+(?:the\s+following\s+)?(?:script|command|code)\s+(?:into|in|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt))\b", "paste_jacking_instruction"),
    (r"(run\s+this\s+(?:command|code)\s+in\s+(?:your\s+)?(?:terminal|shell|console))\b", "paste_jacking_instruction"),
    (r"(website|page|link|site|popup)\s+(?:told|asked|instructed|said|says|wants|tells)\s+(?:me|you|us|him|her)\s+(?:to\s+)?(?:copy|paste|run|execute|type|put|enter)\b", "paste_jacking_instruction"),
    (r"(?:copy|paste|run|execute|type|put|enter)\s+(?:this\s+)?(?:code|command|script|text|thing)?\s*(?:in|into|inside|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command[-\s]?line|prompt|window|box|field)\b", "paste_jacking_instruction"),
    (r"\b(put|type|enter|paste)\s+(?:this\s+)?(?:code|command|script|text|thing)?\s*(?:in|into|inside|to)\s+(?:the\s+)?(?:your\s+)?(?:command[-\s]?line|terminal|shell|console|prompt|window)\b", "paste_jacking_instruction"),
    (r'\b(rm\s+-rf\s+/\s*$|rm\s+-rf\s+~\s*$|rm\s+-rf\s+\$HOME\s*$|rm\s+-rf\s+/\w+|rm\s+-rf\s+/\w+/\w+|mkfs\.|>:\s*\{\}\;|fork\s+bomb)\b', "destructive_command"),
    (r'\b(rm\s+-rf\s+/|rm\s+-rf\s+~|rm\s+-rf\s+\$HOME)\s*$', "destructive_command"),
    (r"\b(dd\s+if=/dev/zero\s+of=/dev/[sh]d[a-z])\b", "destructive_command"),
    (r"\b(sudo\s+)?(chmod\s+\+x\s+/tmp/.*\s*\&\&\s*\S+/tmp/\w+)\b", "download_and_execute_tmp"),
    (r"\b(nc\s+-e\s+|netcat\s+-e\s+)\S|bash\s+-i\s+>&\s+/dev/tcp/", "reverse_shell"),
    (r"\b/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+\s+\|\s*(ba)?sh\b", "reverse_shell"),
    # Browser / AI chat specific
    (r"\b(eval\s*\(|\beval\s*\(|\beval\s+['\"])", "browser_eval"),
    (r"\b(fetch\s*\(\s*['\"]https?://|XMLHttpRequest\s*\(|navigator\.sendBeacon\s*\(\s*['\"]https?://)", "browser_remote_fetch"),
    (r"\b(Worker\s*\(\s*['\"]https?://|SharedWorker\s*\(\s*['\"]https?://|importScripts\s*\(\s*['\"]https?://)", "browser_worker_remote"),
    (r"\b(document\.write\s*\(|document\.body\.innerHTML\s*=)", "browser_dom_injection"),
    (r"\b(localStorage\s*\[\s*['\"]apiKey|sessionStorage\s*\[\s*['\"]apiKey|process\.env\s*\.\s*\w*[kK]ey\w*)", "credential_exfil"),
    (r"\b(prompt\s*\(\s*['\"]Please\s+enter\s+your\s+(?:password|token|key|secret)|confirm\s*\(\s*['\"].*?(?:password|token|key|secret))\b", "browser_credential_phishing"),
]

SUSPICIOUS_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(curl|wget|fetch)\b.*?\|\s*(python[23]?|perl|ruby|node)\b", "remote_fetch_to_interpreter"),
    (r"\b(curl|wget|fetch)\b.*?\s+\|\s*(sudo\s+)?(bash|sh)\s+-s\b", "remote_fetch_to_shell_s"),
    (r"\b(curl|wget|fetch)\b.*?\s+-o\s+/tmp/\w+\s*\;\s*chmod\s*\+x", "remote_fetch_tmp_executable"),
    (r"\b(pip|npm|gem|cargo)\s+install\s+[^\s]+\s*\|\s*(ba)?sh\b", "package_manager_pipe"),
    (r"\b(echo\s+['\"]?[A-Za-z0-9+/=\s]{12,}['\"]?\s*\|\s*base64\s+(-d|--decode))\b", "base64_decode_without_shell"),
    (r"\b(?:openssl|gpg)\s+enc\b.*?\|\s*(ba)?sh\b", "encrypted_payload_to_shell"),
    (r"\b(eval\s*\(|\beval\s+['\"]\$|\bexec\s+\$\(curl)\b", "eval_dynamic_exec"),
    (r"\b(paste\s+(?:this\s+)?(?:code|command|text|script)\s+(?:into|in|inside|to)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt|window))\b", "paste_jacking_instruction"),
    (r"(copy\s+(?:the\s+following\s+)?(?:code|command|script|text|this)\s+(?:into|in|to|inside)\s+(?:the\s+)?(?:your\s+)?(?:terminal|shell|console|command\s+line|prompt|window))\b", "paste_jacking_instruction"),
    (r"\b(disable\s+(?:security|gatekeeper|sip|sudoers|firewall|defender))\b", "security_disable"),
    (r"\b(spctl\s+--master-disable|csrutil\s+disable)\b", "macos_security_disable"),
    (r"\b(Function\s*\(\s*\)|new\s+Function\s*\(\s*['\"].*?\)|setTimeout\s*\(\s*['\"].*?\)|setInterval\s*\(\s*['\"].*?\))", "browser_dynamic_code"),
]

SAFE_INSTALLERS: List[Tuple[str, str]] = [
    (r"https://hermes-agent\.nousresearch\.com/install\.sh", "hermes_official_installer"),
    (r"https://ollama\.com/install\.sh", "ollama_official_installer"),
    (r"https://sh\.rustup\.rs", "rustup_official_installer"),
    (r"https://brew\.sh/.*install", "homebrew_official_installer"),
    (r"https://raw\.githubusercontent\.com/NousResearch/", "hermes_github_raw_installer"),
    (r"https://x\.ai/cli/install\.sh", "xai_official_installer"),
]


def _is_safe_installer(cmd: str) -> bool:
    return any(re.search(pat, cmd, re.IGNORECASE) for pat, _ in SAFE_INSTALLERS)


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


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _try_decode_base64(text: str) -> str:
    m = re.search(r"['\"]([A-Za-z0-9+/=\s]{20,})['\"]\s*\|\s*base64", text)
    if not m:
        return ""
    blob = re.sub(r"\s+", "", m.group(1))
    try:
        return base64.b64decode(blob).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def check(text: str) -> Verdict:
    text = _normalize(text)
    if not text:
        return Verdict("SAFE", 0)

    for pat, reason in BLOCKED_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            if reason == "remote_fetch_to_shell" and _is_safe_installer(text):
                return Verdict("SUSPICIOUS", 1, reasons=[reason, "known_safe_installer_needs_confirmation"], matched=m.group(0))
            return Verdict("DANGEROUS", 2, reasons=[reason], matched=m.group(0))

    decoded = _try_decode_base64(text)
    if decoded:
        for pat, reason in BLOCKED_PATTERNS:
            if re.search(pat, decoded, re.IGNORECASE):
                return Verdict("DANGEROUS", 2, reasons=[f"{reason} (inside decoded payload)"], matched=decoded[:80])
        if re.search(r"\b(curl|wget|bash|sh|exec|eval)\b", decoded, re.IGNORECASE):
            return Verdict("DANGEROUS", 2, reasons=["decoded_base64_contains_shell_commands"], matched=decoded[:80])

    reasons = []
    for pat, reason in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            reasons.append(reason)
    if reasons:
        return Verdict("SUSPICIOUS", 1, reasons=reasons)

    if _is_safe_installer(text):
        return Verdict("SAFE", 0, reasons=["known_safe_installer"])

    return Verdict("SAFE", 0)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        v = check(" ".join(sys.argv[1:]))
        print(v.report())
        sys.exit(v.code)
