#!/usr/bin/env python3
"""Check backup signing key and external trust-anchor health."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from backup_common import read_regular_file, trusted_public_key_path
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY = ROOT / "var" / "keys" / "backup-sign.nacl"
PUBLIC_KEY = ROOT / "var" / "keys" / "backup-sign.nacl.pub"


def validate_regular(path: Path, label: str, errors: list[str]) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        errors.append(f"missing {label}: {path}")
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        errors.append(f"{label} must be one regular file")
        return False
    return True


def main() -> int:
    trust_path = trusted_public_key_path()
    errors: list[str] = []
    valid = all(
        (
            validate_regular(PRIVATE_KEY, "private key", errors),
            validate_regular(PUBLIC_KEY, "public key", errors),
            validate_regular(trust_path, "trust anchor", errors),
        )
    )
    if valid:
        try:
            signing_key = SigningKey(read_regular_file(PRIVATE_KEY, 32))
            public_key = read_regular_file(PUBLIC_KEY, 32)
            trust_key = read_regular_file(trust_path, 32)
            if signing_key.verify_key.encode() != public_key:
                errors.append("private key does not match public key")
            if trust_key != public_key:
                errors.append("external trust anchor does not match public key")
            if stat.S_IMODE(PRIVATE_KEY.lstat().st_mode) != 0o600:
                errors.append("private key permissions must be exactly 0600")
            if stat.S_IMODE(PUBLIC_KEY.lstat().st_mode) & 0o022:
                errors.append("public key must not be group/world writable")
            if stat.S_IMODE(trust_path.lstat().st_mode) & 0o022:
                errors.append("trust anchor must not be group/world writable")
        except (OSError, ValueError) as error:
            errors.append(f"key material is invalid: {error}")

    if errors:
        print("[FAIL] key health check:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[OK] backup signing keypair and trust anchor are healthy")
    print(f"  private: {PRIVATE_KEY}")
    print(f"  public:  {PUBLIC_KEY}")
    print(f"  trust:   {trust_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
