# LYTA Shield Security

**SHIELD: SIGNED BACKUP**

## Threat model

LYTA Shield protects against:
1. Output containing commands that would compromise the host if copied/pasted into a terminal.
2. Adversarial prompts instructing the model to emit dangerous commands.
3. Browser-side prompt injection or credential exfiltration.
4. Local tampering with the LYTA Shield codebase or configuration.

## Verdict levels

- `0` — SAFE
- `1` — SUSPICIOUS (confirm with user)
- `2` — DANGEROUS (block, never execute)

## Backup and signature chain

Every critical file in the repository is protected by a signed backup chain:

1. `scripts/backup-sign.py` creates a tarball of the repository tree, computes SHA-256, and signs the backup with Ed25519.
2. `scripts/verify-backup.py` verifies the SHA-256 and signature against the public key recorded in the manifest.
3. `bin/lyta-shield backup` creates a new signed backup; `bin/lyta-shield verify-backup` checks the latest.
4. If upstream GitHub is unavailable during self-heal, the latest signed backup is used as a fallback restore source.

### Keys

- `var/keys/backup-sign.nacl` — Ed25519 private key (keep secret, never commit).
- `var/keys/backup-sign.nacl.pub` — Ed25519 public key (distributed with the manifest).

Key rotation: `scripts/rotate-backup-key.py` generates a new keypair and re-signs the latest backup.

## Self-heal and integrity

- `bin/lyta-shield restore-baseline` creates a SHA-256 baseline for every tracked file.
- `bin/lyta-shield doctor` checks the baseline, backup status, and circuit breaker.
- `bin/lyta-shield self-heal` restores tampered files from GitHub upstream or the signed backup fallback.
- `bin/lyta-shield incident` logs security events to `var/incidents/`.

## Operational cadence

- Daily backup: `lyta-shield-daily-backup` at 06:30.
- Weekly verification: `lyta-shield-weekly-verify` on Sundays at 07:00.
- Daily self-audit: `lyta-shield-daily-self-audit` at 06:00.
- Doctor/heal: `lyta-shield-doctor-heal` every 10 minutes.

## Reporting

See `self-audit-log.md` for historical incidents and self-audit results.
