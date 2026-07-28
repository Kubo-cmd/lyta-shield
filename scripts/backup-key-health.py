#!/usr/bin/env python3
"""Check backup signing key health."""

import sys
from pathlib import Path

from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

LYTA_DIR = Path(__file__).resolve().parent.parent
PRIV = LYTA_DIR / "var" / "keys" / "backup-sign.nacl"
PUB = LYTA_DIR / "var" / "keys" / "backup-sign.nacl.pub"


def main():
    errors = []
    if not PRIV.exists():
        errors.append(f"missing private key: {PRIV}")
    if not PUB.exists():
        errors.append(f"missing public key: {PUB}")
    if errors:
        print("[FAIL] key health check:")
        for e in errors:
            print(f"  - {e}")
        return 1

    try:
        sk = SigningKey(PRIV.read_bytes())
        vk = sk.verify_key
        pub_bytes = PUB.read_bytes()
        if vk.encode() != pub_bytes:
            errors.append("private key does not match public key")
    except CryptoError as e:
        errors.append(f"key is corrupt: {e}")

    if errors:
        print("[FAIL] key health check:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("[OK] backup signing keypair is healthy")
    print(f"  private: {PRIV}")
    print(f"  public:  {PUB}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
