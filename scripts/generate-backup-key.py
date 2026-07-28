#!/usr/bin/env python3
"""Generate an Ed25519 keypair for backup signing if not present."""
from pathlib import Path
import base64

try:
    import nacl.signing
    import nacl.encoding
except ImportError as e:
    print(f"PyNaCl not available: {e}")
    raise SystemExit(1)

KEY_DIR = Path(__file__).resolve().parent.parent / "var" / "keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)
PRIV = KEY_DIR / "backup-sign.nacl"
PUB = KEY_DIR / "backup-sign.nacl.pub"

if PRIV.exists() and PUB.exists():
    print(f"Keys already exist at {KEY_DIR}")
    raise SystemExit(0)

sk = nacl.signing.SigningKey.generate()
vk = sk.verify_key

PRIV.write_bytes(sk.encode())
PUB.write_bytes(vk.encode())

print(f"Generated Ed25519 keypair:")
print(f"  Private: {PRIV}")
print(f"  Public:  {PUB}")
