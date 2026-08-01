#!/usr/bin/env python3
"""
LYTA Shield — phishing URL rule family (v1.6.0 candidate)

Host-only heuristic classifier for URLs embedded in pasted text.
Local-only by default (zero network, zero burn). Conditions honored:
  GUARDIAN: no default network calls
  CRITIC:   parse real hosts, match host-only, not raw text regex
  CIPHER:   seed blocklist is sha256-pinned and verified at load
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import List, Optional, Tuple

# --- URL extraction -------------------------------------------------------
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s'\"<>|)\]]+", re.IGNORECASE)
_HOST_RE = re.compile(r"^(?:https?://)?(?:[^/@\s]*@)?([^/:?\s]+)", re.IGNORECASE)

# Known free-subdomain / dynamic-DNS hosts abused by the campaign family.
# A URL on one of these is not auto-malicious, but combined with any other
# signal it trips. Kept small and auditable.
FREE_SUBDOMAIN_HOSTS = {
    "ct.ws", "000webhostapp.com", "rf.gd", "byethost.com", "000webhost.com",
    "infinityfreeapp.com", "eu.org", "duckdns.org", "no-ip.com", "ddns.net",
}

# High-abuse TLDs for credential-phish kits.
SUSPECT_TLDS = {".xyz", ".top", ".icu", ".click", ".link", ".live", ".buzz",
                ".online", ".site", ".club", ".loan", ".win", ".cam"}

IP_LITERAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PUNYCODE_RE = re.compile(r"(^|\.)xn--", re.IGNORECASE)

# Brand-lookalike tokens that should never appear in an unknown host.
LOOKALIKE_TOKENS = ("spotify", "login", "verify", "secure", "account", "vote",
                    "wallet", "airdrop", "support", "auth", "signin", "update")


def _extract_hosts(text: str) -> List[str]:
    hosts = []
    for m in _URL_RE.finditer(text):
        h = _HOST_RE.match(m.group(0))
        if h:
            hosts.append(h.group(1).lower().rstrip("."))
    return hosts


def _load_seed_blocklist(path: Optional[Path]) -> Tuple[set, bool]:
    """Load seed blocklist and verify its sha256 digest. Returns (hosts, ok)."""
    if not path or not path.exists():
        return set(), True
    data = json.loads(path.read_text(encoding="utf-8"))
    hosts = set(h.lower() for h in data.get("hosts", []))
    digest = data.get("sha256", "")
    canonical = json.dumps(sorted(hosts), separators=(",", ":")).encode()
    ok = bool(digest) and hashlib.sha256(canonical).hexdigest() == digest
    return hosts, ok


def classify_text(text: str, seed_path: Optional[Path] = None) -> Tuple[int, List[str]]:
    """
    Returns (code, reasons). code: 0 safe, 1 suspicious, 2 dangerous.
    Normalizes host (NFKC) before any comparison so homoglyphs decode.
    """
    reasons: List[str] = []
    worst = 0
    blocked_hosts, seed_ok = _load_seed_blocklist(seed_path)
    if not seed_ok:
        reasons.append("phish_seed_blocklist_tampered_or_unsigned")
        worst = max(worst, 1)

    for raw_host in _extract_hosts(text):
        host = unicodedata.normalize("NFKC", raw_host)
        signals = 0
        # exact seed hit = dangerous outright
        if host in blocked_hosts:
            reasons.append(f"phish_seed_blocklist: {host}")
            worst = max(worst, 2)
            continue
        if IP_LITERAL_RE.match(host):
            reasons.append(f"phish_ip_literal_host: {host}")
            signals += 2
        if PUNYCODE_RE.search(host):
            reasons.append(f"phish_punycode_host: {host}")
            signals += 2
        if host != raw_host:
            reasons.append(f"phish_homoglyph_host: {raw_host}")
            signals += 2
        if any(host.endswith(t) for t in SUSPECT_TLDS):
            reasons.append(f"phish_suspect_tld: {host}")
            signals += 1
        base = host.split(".", 1)[1] if "." in host else host
        if any(host == f or host.endswith("." + f) for f in FREE_SUBDOMAIN_HOSTS):
            reasons.append(f"phish_free_subdomain_host: {host}")
            signals += 1
        if any(tok in host for tok in LOOKALIKE_TOKENS) and signals > 0:
            reasons.append(f"phish_lookalike_token: {host}")
            signals += 1
        if signals >= 2:
            worst = max(worst, 1)
    if worst == 0 and not reasons:
        return 0, []
    return worst, reasons


if __name__ == "__main__":
    import sys
    code, rs = classify_text(" ".join(sys.argv[1:]))
    print(f"[LYTA Shield phish-url] code={code} reasons={rs}")
    sys.exit(code)
