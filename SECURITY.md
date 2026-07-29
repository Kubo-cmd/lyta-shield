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
2. `scripts/verify-backup.py` reconstructs the signed message and verifies it against the external trust anchor. A manifest can never select its own verification key.
3. `bin/lyta-shield backup` creates a new signed backup; `bin/lyta-shield verify-backup` checks the latest.
4. Self-heal accepts repository Git-object bytes or a verified backup member only when the bytes match the pinned per-file integrity digest. It never downloads mutable branch content or calls `extractall()`.

### Keys

- `var/keys/backup-sign.nacl` — Ed25519 private key (keep secret, never commit).
- `var/keys/backup-sign.nacl.pub` — local Ed25519 public key.
- `~/.config/lyta-shield/trusted-backup.pub` — external verification trust anchor. Override with `LYTA_BACKUP_PUBLIC_KEY` when isolation requires another path.

The private key must be one regular file with exact mode `0600`; symlinks and partial keypairs are rejected. Explicit rotation with `scripts/rotate-backup-key.py` updates the keypair and trust anchor. Create a fresh backup immediately afterward because backups signed by the retired key no longer verify against the new anchor.

## Self-heal and integrity

- `bin/lyta-shield restore-baseline` atomically creates a repository-relative SHA-256 baseline for the protected file set.
- `bin/lyta-shield doctor` checks the baseline, backup status, and circuit breaker.
- `bin/lyta-shield self-heal` atomically restores exact baseline bytes and preserves the trusted file mode.
- `bin/lyta-shield incident` logs security events to `var/incidents/`.

## Operational cadence

- Daily backup: `lyta-shield-daily-backup` at 06:30.
- Weekly verification: `lyta-shield-weekly-verify` on Sundays at 07:00.
- Daily self-audit: `lyta-shield-daily-self-audit` at 06:00.
- Doctor/heal: `lyta-shield-doctor-heal` every 10 minutes.

## Reporting

See `self-audit-log.md` for historical incidents and self-audit results.
