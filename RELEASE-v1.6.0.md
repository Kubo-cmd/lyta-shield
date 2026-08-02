# lyta-shield v1.6.0 — Skill Scanner Gate

Local pre-write gate that screens agent skills for dangerous instruction
patterns before they are materialized. Zero network. Zero cost. Runs offline.

## What's new

- **`lyta_skill_scan.py`** — intent-family scanner. Organizes detection around
  attack intent (download-exec, persistence, exfiltration, shell injection,
  destructive ops, typosquats, prompt-injection in prose) rather than a flat
  paste-jack list. Adds linear-time cross-line detection for multi-step attacks.
- **`lyta_scan_gate.py`** — the live gate. `gate_skill_write()` /
  `gate_skill_dir()` raise `SkillGateError` on BLOCK; fail-closed when the
  scanner itself is broken. CLI exits 2 on BLOCK.
- **Standalone / CI mode** — resolves the pattern authority from the script's
  own directory first, then the canonical location, then falls back to
  self-contained baseline patterns. Verified with an empty HOME (no `~/.hermes`).
- **CI gate** — `skill-scan` job runs the red-team corpus and fixture suite on
  every push.

## Why "flawless" is earned this time (honest methodology)

The first 1M-line simulation reported "FLAWLESS — zero missed attacks." That
claim was circular: the synthetic attacks were derived from the scanner's own
pattern tables, so the sim only confirmed the scanner catches what it already
knows. Self-graded homework.

The fix was an independent red team. We built a 41-attack corpus written
attacker-first with no reference to the scanner's internals. First run: 34 of
41 attacks sailed through. That devastating result is what drove the rebuild.

Current verified state (all three suites agree):

- Independent red-team corpus: 41/41 attacks BLOCKed, 0 false positives on 20
  benign fixtures.
- Fixture suite: 14/14 pass, including the live sweep over existing skills.
- 1M-line simulation (seed 1337): 100K/100K attacks caught, 0 false BLOCKs,
  ~65K lines/sec.

The 1M number alone means little. The red-team number is the one that matters.

## Known policy surface (not a scanner bug)

The strict scanner flags 5 of 54 existing reference skills as BLOCK. These are
documentation files that teach `curl | bash` and LaunchAgent patterns inside
live code fences. The scanner is behaving as designed — it surfaces
dangerous-looking instruction patterns for human review. Existing reference
docs are REVIEW-class in practice; only genuinely new writes are hard-gated.

## Install / run

    python3 scripts/skill-scan/lyta_skill_scan_redteam.py   # red-team corpus
    python3 scripts/skill-scan/lyta_skill_scan_test.py      # fixtures + sweep
    python3 scripts/skill-scan/lyta_scan_gate.py <skill_dir>  # gate one skill

Exit codes: 0 clean, 1 review, 2 blocked.
