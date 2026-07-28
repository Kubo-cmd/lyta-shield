#!/usr/bin/env python3
"""Rotate the Ed25519 backup signing keypair.

Usage:
    python3 scripts/rotate-backup-key.py

Saves:
    var/keys/backup-sign.nacl
    var/keys/backup-sign.nacl.pub
"""

import base64
from pathlib import Path

from nacl.signing import SigningKey

LYTA_DIR = Path(__file__).resolve().parent.parent
KEY = LYTA_DIR / "var" / "keys" / "backup-sign.nacl"
PUB = LYTA_DIR / "var" / "keys" / "backup-sign.nacl.pub"

signing_key = SigningKey.generate()
verify_key = signing_key.verify_key

KEY.write_bytes(signing_key.encode())
PUB.write_bytes(verify_key.encode())

print("[OK] rotated backup signing key")
print(f"[INFO] public key: {base64.b64encode(verify_key.encode()).decode()}")
print(f"[INFO] files: {KEY}, {PUB}")
