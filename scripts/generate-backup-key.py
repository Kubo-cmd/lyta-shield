#!/usr/bin/env python3
"""Generate or validate the backup signing key and external trust anchor."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from backup_common import read_regular_file, trusted_public_key_path
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent.parent
KEY_DIR = ROOT / "var" / "keys"
PRIVATE_KEY = KEY_DIR / "backup-sign.nacl"
PUBLIC_KEY = KEY_DIR / "backup-sign.nacl.pub"


def exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def require_single_regular(path: Path, label: str) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"{label} must be one regular file")


def write_exclusive(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short key write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if KEY_DIR.is_symlink() or not KEY_DIR.is_dir():
        raise SystemExit("key directory must be a real directory")
    os.chmod(KEY_DIR, 0o700)

    private_exists = exists_without_following(PRIVATE_KEY)
    public_exists = exists_without_following(PUBLIC_KEY)
    if private_exists != public_exists:
        raise SystemExit("incomplete keypair; remove or recover it before generating")

    if private_exists:
        require_single_regular(PRIVATE_KEY, "private key")
        require_single_regular(PUBLIC_KEY, "public key")
        signing_key = SigningKey(read_regular_file(PRIVATE_KEY, 32))
        public_key = read_regular_file(PUBLIC_KEY, 32)
        if signing_key.verify_key.encode() != public_key:
            raise SystemExit("existing keypair does not match")
    else:
        signing_key = SigningKey.generate()
        public_key = signing_key.verify_key.encode()
        try:
            write_exclusive(PRIVATE_KEY, signing_key.encode(), 0o600)
            write_exclusive(PUBLIC_KEY, public_key, 0o644)
        except BaseException:
            PRIVATE_KEY.unlink(missing_ok=True)
            PUBLIC_KEY.unlink(missing_ok=True)
            raise

    os.chmod(PRIVATE_KEY, 0o600)
    os.chmod(PUBLIC_KEY, 0o644)

    trust_path = trusted_public_key_path()
    trust_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    trust_exists = exists_without_following(trust_path)
    if trust_exists:
        require_single_regular(trust_path, "trust anchor")
        if read_regular_file(trust_path, 32) != public_key:
            raise SystemExit(f"trust anchor mismatch: {trust_path}")
    else:
        write_exclusive(trust_path, public_key, 0o644)
    os.chmod(trust_path, 0o644)

    print(f"private: {PRIVATE_KEY}")
    print(f"public:  {PUBLIC_KEY}")
    print(f"trust:   {trust_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
