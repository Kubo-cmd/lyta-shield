# LYTA Shield Security

**SHIELD: SIGNED BACKUP**

## Threat model

LYTA Shield guards the Hermes output channel before it reaches the user. The primary risks are:

- An agent produces a shell command or instruction that exfiltrates data, destroys files, or escalates privileges.
- The guard itself is tampered with or bypassed locally.
- The upstream GitHub repository is unreachable, so self-heal cannot fetch known-good files.

## Defense layers

1. **Hermes guard (`integrations/hermes_guard.py`)** — scans every assistant output for DANGEROUS patterns, unsafe commands, and policy violations.
2. **Wrapper (`integrations/hermes-wrapper.sh`)** — intercepts the Hermes CLI and routes every response through the guard.
3. **Circuit breaker** — trips after 3 DANGEROUS events in the last 10 outputs, requiring manual reset.
4. **Integrity baseline** — `lyta-shield restore-baseline` records SHA-256 hashes of every file in the tree.
5. **Trust-anchor pin** — `lyta-shield lock` freezes the baseline and disables self-heal; `lyta-shield unlock` removes the pin.
6. **Self-heal** — `lyta-shield self-heal` compares files against the baseline, fetches known-good copies from upstream GitHub, and falls back to a signed local backup if the network is down.
7. **Signed backup** — `lyta-shield backup` creates a tarball of the entire tree, signs it with an Ed25519 key, and stores the manifest in `var/backups/`.

## Backup and signature chain

Keys are stored in `var/keys/`:

- `backup-sign.nacl` — private Ed25519 signing key (do not commit).
- `backup-sign.nacl.pub` — public key.

The backup command:

```bash
lyta-shield backup
```

produces:

- `var/backups/lyta-shield-<timestamp>.tar.gz`
- `var/backups/lyta-shield-<timestamp>.tar.gz.sig`
- `var/backups/lyta-shield-<timestamp>.manifest`

The manifest contains the SHA-256 digest, the tarball name, the signature, and the public key. The signed message is:

```
lyta-shield-backup|sha256|<digest>|<tarball>
```

Verify the latest backup:

```bash
lyta-shield verify-backup
```

Or verify a specific manifest:

```bash
lyta-shield verify-backup var/backups/lyta-shield-20260728084311.manifest
```

## Self-heal fallback

When `self-heal` detects a tampered file, it first tries to restore from the upstream raw URL on GitHub. If the network fails (404, offline, etc.), it automatically extracts the file from the most recent signed backup after verifying the backup signature and SHA-256.

## Key rotation

To rotate the backup signing key:

```bash
python3 scripts/rotate-backup-key.py
lyta-shield backup
lyta-shield restore-baseline
```

After rotation, old backups can still be verified with the old public key, but new backups will use the new key.

## Audit

- `lyta-shield status` — live health and last events.
- `lyta-shield incident` — all DANGEROUS events.
- `lyta-shield doctor` — full health, integrity, and backup verification.
- `self-audit-log.md` — manual self-audit trail.
