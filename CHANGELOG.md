# LYTA Shield Changelog

## v1.5.0

- Fail closed when the terminal guard is missing, unsafe, or exits unexpectedly, while preserving visible diagnostics.
- Require a reviewed SHA-256 pin for the optional Codex Security executable and revalidate it immediately before execution.
- Reject symlink, hard-link, non-owner, and non-regular telemetry log targets.
- Remove unauthenticated remote multi-file installation; installs now stage a complete local release snapshot before replacement.
- Scope safe-installer and educational-context downgrades to prevent unrelated text and nested URLs from weakening dangerous matches.
- Restore browser/Python parity for zsh fetch pipelines, destructive flag permutations, Unicode normalization, and focused JavaScript evaluation rules.
- Add a hash-locked build toolchain, commit-pinned CI actions, clean-snapshot reproducibility checks, deterministic CycloneDX SBOM generation, provenance attestation, and tag-triggered release automation.

## v1.4.2

- Reject symlinks, hard links, and special files during signed-backup creation, including path-swap checks at archive time.
- Remove partial backup archives after fail-closed creation errors.
- Add a regression that proves external symlink targets cannot enter signed backups.
- Add a permanent release-version synchronization regression.
- Build, install, and execute both wheel and source distributions in CI.

## v1.4.1

- Added the missing `lyta-shield` console entry point to wheel installations.
- Verified the published wheel in a clean Python 3.11 environment.

## v1.4.0

- Hardened the Hermes wrapper to inspect failed-command output, validate guard JSON strictly, and suppress dangerous content before rendering.
- Made safe-installer exceptions compositional so later dangerous commands remain blocked.
- Added browser paste, submit, and keyboard bypass interception with text-only warning rendering.
- Rebuilt signed backups around an external Ed25519 trust anchor, strict key-file checks, safe archive validation, and exact-digest self-healing.
- Added bounded chat-log auditing, loopback-first metrics, strict doctor failure propagation, and script-only zero-burn maintenance jobs.
- Added an offline-first Codex Security SARIF bridge with pinned upstream metadata, secret-stripped dry runs, bounded reports, and symlink-safe output.
- Expanded critical-path regression coverage and CI to 92 tests across Python 3.10–3.12.
- Removed tracked runtime event logs and scrubbed identity-bearing repository metadata.

## v1.3.1

- Added `lyta-shield key-health` command to check Ed25519 backup signing keypair.
- Backup now auto-generates a new keypair if the signing key is missing.
- Added `scripts/backup-key-health.py` for key health checks.
- Fixed `SECURITY.md` to document the signed backup chain and operational cadence.
- Created `var/hermes-guard-events.jsonl` so the doctor no longer reports a missing event log.
- CI workflow now installs `pynacl` and runs `backup-key-health` before backup.
- Refreshed integrity baseline to cover 43 files.

## v1.3.0

- Signed backup chain with Ed25519 signatures and SHA-256 verification.
- `lyta-shield backup` and `verify-backup` commands.
- Self-heal fallback to signed backup when upstream GitHub is unavailable.
- Full-tree integrity baseline (`restore-baseline`, `doctor`, `self-heal`).
- Pytest test suite for rules, adversarial bypass, and backup tests.
- GitHub Actions CI workflow for rules tests, backup/verify, and lint.
- Hermes cron jobs: `lyta-shield-daily-backup`, `lyta-shield-weekly-verify`.
