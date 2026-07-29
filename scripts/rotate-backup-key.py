#!/usr/bin/env python3
"""Explicitly rotate a healthy Ed25519 backup keypair and trust anchor."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from backup_common import read_regular_file, trusted_public_key_path
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent.parent
KEY_DIR = ROOT / "var" / "keys"
PRIVATE_KEY = KEY_DIR / "backup-sign.nacl"
PUBLIC_KEY = KEY_DIR / "backup-sign.nacl.pub"


def require_single_regular(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise SystemExit(f"missing {label}; initialize keys before rotation") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"{label} must be one regular file")


def staged_file(path: Path, data: bytes, mode: int) -> Path:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def main() -> int:
    trust_path = trusted_public_key_path()
    for path, label in (
        (PRIVATE_KEY, "private key"),
        (PUBLIC_KEY, "public key"),
        (trust_path, "trust anchor"),
    ):
        require_single_regular(path, label)

    current = SigningKey(read_regular_file(PRIVATE_KEY, 32))
    current_public = read_regular_file(PUBLIC_KEY, 32)
    current_trust = read_regular_file(trust_path, 32)
    if current.verify_key.encode() != current_public or current_public != current_trust:
        raise SystemExit("refusing rotation because the current trust chain is unhealthy")
    if stat.S_IMODE(PRIVATE_KEY.lstat().st_mode) != 0o600:
        raise SystemExit("private signing key permissions must be 0600")

    replacement = SigningKey.generate()
    replacement_public = replacement.verify_key.encode()
    staged: list[tuple[Path, Path]] = []
    try:
        staged.append((staged_file(PRIVATE_KEY, replacement.encode(), 0o600), PRIVATE_KEY))
        staged.append((staged_file(PUBLIC_KEY, replacement_public, 0o644), PUBLIC_KEY))
        staged.append((staged_file(trust_path, replacement_public, 0o644), trust_path))
        for temporary, destination in staged:
            os.replace(temporary, destination)
        for directory in {KEY_DIR, trust_path.parent}:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)

    print("[OK] rotated backup signing key and external trust anchor")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
