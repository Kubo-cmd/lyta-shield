# LYTA Shield Changelog

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
