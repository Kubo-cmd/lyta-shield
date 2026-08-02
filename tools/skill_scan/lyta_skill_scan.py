#!/usr/bin/env python3
"""
lyta_skill_scan.py — scan-before-run security screen for Hermes/LYTA skills.

The gap (per Goose recipe-scanner digest, 2026-07-31): skill_manage writes
SKILL.md + scripts with no pre-landing security screen. This is the adapter
that closes it — it REUSES the proven static patterns from
lyta_supply_chain_scanner.py (no forked regex set) and points them at skill
content (SKILL.md body, scripts/, references/, templates/) instead of
lyta_core.

Design (Council of 9 binding conditions):
  - Adapter over authority: imports patterns/allowlists from the existing
    supply-chain scanner; does NOT vendor a second scanner or runtime.
  - Static regex only. NEVER executes scanned content. Fail-closed.
  - Report-only verdict for EXISTING skills (false-positive safety, ORACLE).
  - Block-with-reason verdict available for NEW writes (gate mode).
  - Zero-burn: pure local analysis, no network, no credentials.

Verdicts: CLEAN (no findings) · REVIEW (suspicious, human/agent look) ·
          BLOCK (high-confidence dangerous: shell exec of remote payload,
          eval/exec of fetched data, credential exfil pattern).

Usage:
  python3 lyta_skill_scan.py --skill-dir ~/.hermes/skills/lyta-repo-digest
  python3 lyta_skill_scan.py --all-skills            # report-only sweep
  python3 lyta_skill_scan.py --gate path/to/SKILL.md # block-with-reason
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CORE = Path.home() / ".hermes" / "lyta_core"
SKILLS_ROOT = Path.home() / ".hermes" / "skills"

# --- Reuse existing authority: import the proven scanner's patterns. ---------
# Resolution order: (1) the directory containing THIS file (vendored/CI copy),
# (2) the canonical lyta_core location (live workstation). If the import fails
# we fall back to SELF-CONTAINED baseline patterns so the gate still screens in
# standalone/CI mode. Adapters over authorities — never a permissive scan.
_HERE = Path(__file__).resolve().parent
for _p in (str(_HERE), str(CORE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
_PATTERNS_SOURCE = "lyta_supply_chain_scanner"
try:
    import lyta_supply_chain_scanner as _scs
    EXEC_PATTERN = _scs.EXEC_PATTERN
    SHELL_TRUE_PATTERN = _scs.SHELL_TRUE_PATTERN
    REMOTE_IMPORT_PATTERN = _scs.REMOTE_IMPORT_PATTERN
    ALLOWED_CONTEXTS = _scs.ALLOWED_CONTEXTS
    _IMPORT_OK = True
except Exception:
    # Standalone/CI fallback: conservative self-contained review patterns.
    _PATTERNS_SOURCE = "standalone-fallback"
    EXEC_PATTERN = re.compile(r"\b(eval|exec)\s*\(", re.I)
    SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True", re.I)
    REMOTE_IMPORT_PATTERN = re.compile(r"\burlopen\s*\(|requests\.(get|post)\s*\(", re.I)
    ALLOWED_CONTEXTS = {"urlopen": [re.compile(r"(api\.openai\.com|api\.telegram\.org|github\.com|api\.github\.com)", re.I)]}
    _IMPORT_OK = True  # fallback is functional; not a fail-closed state

# Skill-specific high-confidence DANGEROUS patterns. Organized by ATTACK INTENT
# (independent red-team corpus 2026-07-31 found the original paste-jack-only set
# missed 34/41 attacker-first cases). Each family is a goal, not a regex echo.
BLOCK_PATTERNS = [
    # --- FAMILY: remote download -> interpreter (paste-jack classic) ---
    (re.compile(r"curl[^|\n]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|perl|ruby)\b", re.I),
     "pipe remote download straight into an interpreter"),
    (re.compile(r"wget[^|\n]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|perl|ruby)\b", re.I),
     "pipe remote download straight into an interpreter"),
    (re.compile(r"(curl|wget)[^\n]*https?://[^\n]*(-o|-O|>)\s*\S+\.(sh|bash|py|pl|rb)\b[^\n]*(&&|;|\n)\s*(sudo\s+)?(bash|sh|zsh|python3?|perl|ruby|chmod\s*\+x)", re.I),
     "download script to file then execute it"),

    # --- FAMILY: download-and-execute without a literal pipe ---
    (re.compile(r"(curl|wget)[^\n]*https?://[^\n]*(&&|;)[^\n]*(chmod\s*\+x|bash\s|sh\s|python3?\s|\./|/tmp/)", re.I),
     "download then chmod/run in one line"),
    (re.compile(r"urllib\.request\.urlopen\([^\n]*\)\.read\(\)[^\n]*\)?\s*\)?\s*;?\s*$", re.I),  # placeholder; real one below
     "urlopen fetch"),
    (re.compile(r"exec\s*\(\s*(urllib\.request\.)?urlopen\(", re.I),
     "exec() of urlopen-fetched remote content"),
    (re.compile(r"getstore\([^\n]*\)\s*;\s*system\(", re.I),
     "perl download then system() run"),

    # --- FAMILY: encoded-payload execution ---
    (re.compile(r"base64\s+(-d|--decode|-D)[^|\n]*\|\s*(bash|sh|zsh|python3?)\b", re.I),
     "base64-decode piped to an interpreter (paste-jack)"),
    (re.compile(r"base64\s+(-d|--decode|-D)[^\n]*>\s*\S+[^\n]*(;|&&)[^\n]*(bash|sh|zsh|python3?)\s", re.I),
     "base64-decode to file then run"),
    (re.compile(r"exec\s*\(\s*base64\.b64decode\(", re.I),
     "python exec() of base64-decoded payload"),
    (re.compile(r"(eval|exec)\s*\(\s*__import__\(\s*['\"]base64['\"]\s*\)\.b64decode\(", re.I),
     "eval/exec of __import__('base64').b64decode payload"),
    (re.compile(r"(eval|exec)\s*\(\s*(requests\.(get|post)|urllib\.request\.urlopen|urlopen)\s*\(", re.I),
     "eval/exec of remotely-fetched content"),
    (re.compile(r"(eval|exec)\s*\(\s*\w+\.(get|post)\([^)]*\)\.(text|content|read\(\))\s*\)", re.I),
     "eval/exec of HTTP response body"),
    (re.compile(r"openssl\s+enc\s+-base64\s+-d[^\n]*\|\s*(bash|sh|zsh)\b", re.I),
     "openssl base64 decode piped to shell"),
    (re.compile(r"printf[^\n]*\\x[0-9a-f]{2}[^\n]*\|\s*xargs[^\n]*sh\s+-c", re.I),
     "hex-obfuscated command rebuilt and executed"),

    # --- FAMILY: reverse / bind shells ---
    (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.I),
     "bash reverse shell over /dev/tcp"),
    (re.compile(r"\bnc(at)?\s+(-\S*\s+)*-e\s+/(bin/)?(sh|bash)", re.I),
     "netcat -e exec shell"),
    (re.compile(r"socket\.socket\(\)[^\n]*connect\([^\n]*\)[^\n]*(dup2|pty\.spawn|/bin/sh)", re.I),
     "python reverse shell (socket+dup2)"),
    (re.compile(r"mkfifo[^\n]*\|[^\n]*(/bin/)?(sh|bash)[^\n]*\|[^\n]*nc(at)?\s", re.I),
     "mkfifo netcat shell relay"),
    (re.compile(r"socat\s+exec:[^\n]*(bash|sh)[^\n]*tcp:", re.I),
     "socat reverse shell"),

    # --- FAMILY: destructive filesystem / sabotage ---
    # Only mass-deletion / disk-targeting. `rm -f <specific file>` is normal
    # cleanup (tempfiles, lockfiles) and is NOT blocked — require a mass target
    # (root, bare home, glob, current-dir-wipe, or trailing-slash dir tree).
    (re.compile(r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+(/\s*$|/\s|~\s*$|~/\s*\*|$HOME\s*$|\.\s*$|\*\s*$|\S+/\s*$)", re.I),
     "destructive rm of root/home/everything"),
     (re.compile(r"(os\.system|subprocess[.\w]*)\s*\(\s*['\"][^'\"]*(rm\s+-rf\s+/|mkfs|dd\s+if=)", re.I),
      "destructive filesystem command"),
     (re.compile(r"\bmkfs(\.\w+)?\s+/dev/", re.I),
      "format a device"),
     (re.compile(r"\bdd\s+if=/dev/(zero|random|urandom)\s+of=/dev/(disk|sd|nvme)", re.I),
      "raw write over a disk device"),
     (re.compile(r"\bfind\s+~\s+[^\n]*-delete\b", re.I),
      "find-and-delete under home"),
     (re.compile(r"chmod\s+-R\s+0{3}\s+[^\n]*(\.ssh|\.gnupg|~|/)", re.I),
      "lockout chmod on keys/home"),
     (re.compile(r"git\s+clean\s+-fdx?[^\n]*(&&|;)[^\n]*git\s+reset\s+--hard", re.I),
      "repo wipe (clean+hard reset chained)"),

    # --- FAMILY: hardcoded credentials ---
    (re.compile(r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET|GH_TOKEN|GITHUB_TOKEN)[^=]*=\s*['\"]?((?!\.\.\.|\*\*\*|\$\{|<|your|xxx|example)[A-Za-z0-9_\-]{16,})", re.I),
     "hardcoded credential literal"),

    # --- FAMILY: exfiltration endpoints & secret sending ---
    (re.compile(r"(api\.telegram\.org|discord(app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|requestbin|ngrok)", re.I),
     "data sent to a webhook/exfil endpoint"),
    (re.compile(r"\$\{?\w*(KEY|SECRET|TOKEN|PASSWD?|CREDENTIAL)\w*\}?[^|\n]*\|\s*(curl|wget|nc|netcat)\b", re.I),
     "credential piped to a network send"),
    (re.compile(r"(curl|wget)\b[^\n]*(--data|-d|--data-binary|--upload-file|-T)\s+@?-?\s*\$\{?\w*(KEY|SECRET|TOKEN|CREDENTIAL)", re.I),
     "credential sent as request body"),
    (re.compile(r"\benv\b[^\n]*\|\s*(curl|nc|netcat|wget)\b[^\n]*(-d|--data|POST)", re.I),
     "environment dump piped to network send"),
    (re.compile(r"(cat|tar\s+c\w*\s*-?)[^\n]*(\.ssh|id_rsa|\.aws|\.gnupg|\.env)[^\n]*\|\s*[^\n]*(nc|netcat|curl|base64[^\n]*\|\s*curl)", re.I),
     "keys/creds archived or piped toward network"),
    (re.compile(r"history\s*\|[^\n]*\bmail\b", re.I),
     "shell history mailed out"),
    (re.compile(r"security\s+find-(generic|internet)-password[^\n]*\|\s*(curl|nc|netcat)", re.I),
     "macOS keychain dump piped to network"),
    (re.compile(r"(secretsmanager|get-secret-value)[^\n]*(&&|;|\|)[^\n]*(curl|nc|netcat|base64[^\n]*curl)", re.I),
     "cloud secret store piped to network"),

    # --- FAMILY: persistence mechanisms ---
    (re.compile(r"crontab\b[^\n]*(curl|wget|bash|sh)[^\n]*https?://", re.I),
     "cron job fetching remote payload"),
    (re.compile(r"LoginHook|com\.apple\.loginwindow[^\n]*LoginHook", re.I),
     "macOS login-hook persistence"),
    (re.compile(r"LaunchAgents/[^\n]*\.plist[^\n]*(launchctl\s+load|Program</key>)", re.I),
     "LaunchAgent persistence install"),
    (re.compile(r"(>>|>)\s*~/\.(zshrc|bashrc|bash_profile|profile|zprofile)[^\n]*(source|curl|wget|bash|sh|evil|payload)", re.I),
     "shell rc-file persistence injection"),

    # --- FAMILY: supply-chain / typosquat install channels ---
    (re.compile(r"pip(3)?\s+install[^\n]*--index-url\s+https?://(?!pypi\.org|pypi\.python\.org)", re.I),
     "pip install from rogue index URL"),
    (re.compile(r"npm\s+install[^\n]*--registry\s+https?://(?!registry\.npmjs\.org)", re.I),
     "npm install from rogue registry"),
    (re.compile(r"(git\s+clone\s+https?://\S+)[^\n]*(&&|;)[^\n]*(make\s+install|bash\s+install|sh\s+install|\./configure|setup\.py\s+install)", re.I),
     "clone untrusted repo then build/install"),
    # Shell rc-file append = persistence regardless of payload keyword.
    (re.compile(r">>\s*~/\.(zshrc|bashrc|bash_profile|profile|zprofile|zlogin)\b", re.I),
     "append to shell rc file (persistence vector)"),
    # Known typosquats of top packages (small curated set; not general spellcheck).
    (re.compile(r"\b(pip3?|npm)\s+install\s+(reqeusts|requets|lodahs|lodach|colurama|colourama|python-dateutil2|urllib3s|brotli-|numpi|pytohn)\b", re.I),
     "likely package typosquat install"),

    # --- FAMILY: prompt-injection aimed at the AGENT (prose attacks) ---
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
     "prompt-injection: ignore previous instructions"),
    (re.compile(r"(SYSTEM|<<SYS>>|\[INST\]|<\|im_start\|>)\s*[:\]]?\s*(ignore|forget|override|new\s+(task|instruction))", re.I),
     "prompt-injection: fake system/inst tag"),
    (re.compile(r"(you\s+are\s+now\s+in|entering)\s+(maintenance|developer|debug|admin|unrestricted)\s+mode", re.I),
     "prompt-injection: mode-override jailbreak"),
    (re.compile(r"(note|attention|instruction)\s+to\s+the\s+(ai|assistant|agent|llm|model)\b[^\n]*(run|execute|curl|post|send|delete|ignore)", re.I),
     "prompt-injection: direct instruction to the agent"),
    (re.compile(r"(the\s+agent|assistant)\s+(must|should|shall)\s+(silently\s+)?(execute|run|curl|post)[^\n]*without\s+(telling|informing|asking)", re.I),
     "prompt-injection: covert-action instruction"),
]

# Reasons that stay BLOCK-class even inside markdown prose (injection hides in docs)
# and data files (paste-jack payload delivered as a string).
_PROSE_KEEP_BLOCK = {
    "base64-decode piped to an interpreter (paste-jack)",
    "data sent to a webhook/exfil endpoint",
    "prompt-injection: ignore previous instructions",
    "prompt-injection: fake system/inst tag",
    "prompt-injection: mode-override jailbreak",
    "prompt-injection: direct instruction to the agent",
    "prompt-injection: covert-action instruction",
}

SCANNABLE_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".md", ".yaml", ".yml", ".json", ".toml"}

# Known-benign contexts: lines matching these are downgraded from BLOCK to REVIEW
# (not silently passed — they still surface for a human). ORACLE false-positive
# guard: official install pipes, localhost API pipes, specific-file cleanup.
_BENIGN_PIPE_SOURCES = re.compile(
    r"(ollama\.com|astral\.sh|get\.docker\.com|cli\.inference\.sh|sh\.rustup\.rs|"
    r"raw\.githubusercontent\.com/\S+/(install|setup)|127\.0\.0\.1|localhost)", re.I)
_BENIGN_RM_SPECIFIC = re.compile(r"\brm\s+-f\s+[^\s]*\.(tmp|lock|sh|pid|log)\b", re.I)


def _line_allowed(line: str, category: str) -> bool:
    for pat in ALLOWED_CONTEXTS.get(category, []):
        if pat.search(line):
            return True
    return False


def _is_markdown_fence_prose(line: str, in_code_block: bool) -> bool:
    """In a .md file, only flag lines inside ``` fences (real instructions),
    not descriptive prose. Returns True if the line should be SKIPPED."""
    return not in_code_block


def scan_file(path: Path) -> list[dict]:
    findings = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return findings
    is_md = path.suffix.lower() == ".md"
    # Pure data files (.json/.yaml/.toml) hold regex/credential strings as DATA,
    # not executable lines — a "match": "curl ... Bearer ***" entry in a skill
    # index is a detection rule, not a command. Demote block-class to REVIEW here
    # (except the _PROSE_KEEP_BLOCK injection/paste-jack classes, which are
    # dangerous even as strings).
    is_data = path.suffix.lower() in {".json", ".yaml", ".yml", ".toml"}
    # Executable scripts get the full block treatment. Markdown is prose: most
    # install/exec patterns outside code fences are descriptive and downgrade to
    # REVIEW, but prompt-injection and paste-jack classes stay BLOCK anywhere
    # (they ARE the attack when written in prose). Red-team 2026-07-31 proved
    # injection hides OUTSIDE code fences, so .md prose is scanned, not skipped.
    in_code = False
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if is_md and line.startswith("```"):
            in_code = not in_code
            continue
        if not line or (line.startswith("#") and not is_md):
            continue
        # Markdown prose is scanned for the keep-block classes only; markdown
        # code fences are scanned for everything. Scripts/data scan everything.
        prose_only = is_md and not in_code

        # BLOCK class first (high confidence).
        for pat, reason in BLOCK_PATTERNS:
            if not pat.search(line):
                continue
            if reason in _PROSE_KEEP_BLOCK:
                # Dangerous in ANY context — prose, code, data.
                findings.append({"file": path.name, "line": i, "severity": "BLOCK",
                                 "risk": reason, "context": line[:90]})
                break
            if prose_only:
                # Descriptive prose mention of an exec idiom — REVIEW, not BLOCK.
                findings.append({"file": path.name, "line": i, "severity": "REVIEW",
                                 "risk": reason + " (in prose)", "context": line[:90]})
                break
            # Known-benign source/target downgrade (official installs, localhost,
            # specific-file cleanup): surface as REVIEW, not silent pass.
            benign_ctx = (
                (reason == "pipe remote download straight into an interpreter" and _BENIGN_PIPE_SOURCES.search(line)) or
                (reason == "destructive rm of root/home/everything" and _BENIGN_RM_SPECIFIC.search(line))
            )
            if benign_ctx:
                findings.append({"file": path.name, "line": i, "severity": "REVIEW",
                                 "risk": reason + " (known-benign source)", "context": line[:90]})
                break
            sev = "REVIEW" if is_data else "BLOCK"
            findings.append({"file": path.name, "line": i, "severity": sev,
                             "risk": reason, "context": line[:90]})
            break
        else:
            # REVIEW class: reused risky-idiom patterns (respect allowlists).
            if prose_only:
                continue
            if SHELL_TRUE_PATTERN and SHELL_TRUE_PATTERN.search(line) and not _line_allowed(line, "shell_true"):
                findings.append({"file": path.name, "line": i, "severity": "REVIEW",
                                 "risk": "shell=True usage", "context": line[:90]})
            if EXEC_PATTERN:
                for m in EXEC_PATTERN.finditer(line):
                    if "re.compile" in line or "ast.literal_eval" in line or _line_allowed(line, "eval"):
                        continue
                    findings.append({"file": path.name, "line": i, "severity": "REVIEW",
                                     "risk": f"dangerous exec idiom: {m.group(1)}", "context": line[:90]})
                    break
            if REMOTE_IMPORT_PATTERN and REMOTE_IMPORT_PATTERN.search(line) and not _line_allowed(line, "urlopen"):
                findings.append({"file": path.name, "line": i, "severity": "REVIEW",
                                 "risk": "remote fetch idiom", "context": line[:90]})

    # --- Cross-line detection: payloads split across lines evade per-line scan.
    # Position-based (linear time), NOT nested-wildcard regex (catastrophic
    # backtracking on large files — caused 60s+ hangs during full sweep).
    body = "\n".join(lines)
    cross = []
    # find a downloaded script filename, then check if it's executed later
    dl = re.search(r"(?:curl|wget)[^\n]*https?://[^\n]*(?:-o|-O|>)\s*(\S+)", body, re.I)
    if dl:
        fname = dl.group(1)
        # executed by an interpreter, or chmod+x then run by path
        if re.search(r"(?:^|\n)\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|perl|ruby)\s+" + re.escape(fname) + r"\b", body, re.I):
            cross.append("download to file then execute (cross-line)")
        elif re.search(r"chmod\s*\+x\s+" + re.escape(fname) + r"\b", body, re.I) and re.search(re.escape(fname) + r"\s*$", body, re.M):
            cross.append("download, chmod, then run by path (cross-line)")
    # LaunchAgent plist written ... then loaded
    if "LaunchAgents/" in body and ".plist" in body and re.search(r"launchctl\s+(load|bootstrap)", body, re.I):
        cross.append("LaunchAgent plist write + load (cross-line persistence)")
    for reason in cross:
        findings.append({"file": path.name, "line": 0, "severity": "BLOCK",
                         "risk": reason, "context": "(multi-line)"})
    return findings


def scan_skill_dir(skill_dir: Path) -> dict:
    skill_dir = Path(skill_dir)
    if not skill_dir.is_dir():
        return {"skill": str(skill_dir), "error": "not a directory", "verdict": "REVIEW"}
    findings = []
    scanned = 0
    for f in sorted(skill_dir.rglob("*")):
        if not f.is_file() or f.suffix.lower() not in SCANNABLE_EXT:
            continue
        if "__pycache__" in f.parts or f.name.startswith("."):
            continue
        scanned += 1
        findings.extend(scan_file(f))
    blocks = [x for x in findings if x["severity"] == "BLOCK"]
    reviews = [x for x in findings if x["severity"] == "REVIEW"]
    verdict = "BLOCK" if blocks else ("REVIEW" if reviews else "CLEAN")
    return {"skill": skill_dir.name, "path": str(skill_dir), "files_scanned": scanned,
            "verdict": verdict, "block_count": len(blocks), "review_count": len(reviews),
            "findings": findings}


def main() -> int:
    ap = argparse.ArgumentParser(description="LYTA skill scan-before-run screen")
    ap.add_argument("--skill-dir", help="scan one skill directory")
    ap.add_argument("--all-skills", action="store_true", help="report-only sweep of every skill")
    ap.add_argument("--gate", help="block-with-reason gate on a SKILL.md or dir (exit 1 on BLOCK)")
    args = ap.parse_args()

    if not _IMPORT_OK:
        print(json.dumps({"error": f"failed to import {_PATTERNS_SOURCE}; failing closed",
                          "verdict": "BLOCK"}, indent=2))
        return 1

    if args.all_skills:
        results = [scan_skill_dir(d) for d in sorted(SKILLS_ROOT.iterdir()) if d.is_dir()]
        summary = {"skills_scanned": len(results),
                   "clean": sum(1 for r in results if r["verdict"] == "CLEAN"),
                   "review": sum(1 for r in results if r["verdict"] == "REVIEW"),
                   "block": sum(1 for r in results if r["verdict"] == "BLOCK"),
                   "flagged": [r for r in results if r["verdict"] != "CLEAN"]}
        print(json.dumps(summary, indent=2))
        return 0  # report-only on existing skills

    target = args.skill_dir or args.gate
    if not target:
        ap.error("provide --skill-dir, --all-skills, or --gate")
    p = Path(target).expanduser()
    result = scan_skill_dir(p if p.is_dir() else p.parent) if p.is_dir() or p.suffix else scan_skill_dir(p.parent)
    if args.gate and p.is_file():
        result = {"skill": p.name, "path": str(p), "files_scanned": 1,
                  **{k: v for k, v in scan_skill_dir(p.parent).items() if k not in ("skill", "path", "files_scanned")}}
    print(json.dumps(result, indent=2))
    print("\nPATTERN PERSISTS.", file=sys.stderr)
    return 1 if (args.gate and result["verdict"] == "BLOCK") else 0


if __name__ == "__main__":
    sys.exit(main())
