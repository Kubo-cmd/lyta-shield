#!/usr/bin/env python3
"""Create a compressed backup and a trust-anchored Ed25519 manifest."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path

from backup_common import (
    ALGORITHM,
    SCHEMA_VERSION,
    canonical_message,
    read_regular_file,
    sha256_regular_file,
)
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent.parent
BACKUP_DIR = ROOT / "var" / "backups"
PRIVATE_KEY = ROOT / "var" / "keys" / "backup-sign.nacl"
PUBLIC_KEY = ROOT / "var" / "keys" / "backup-sign.nacl.pub"

EXCLUDED_PARTS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
}
EXCLUDED_NAMES = {".DS_Store", ".coverage", ".env", "hermes-guard-events.jsonl"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".key", ".pem"}


def include_path(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if relative.parts[:2] in {("var", "backups"), ("var", "keys")}:
        return False
    if path.name in EXCLUDED_NAMES or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return False
    return True


def safe_archive_filter(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Reject links and special files even if a path changes after lstat()."""
    if not (info.isfile() or info.isdir()):
        raise ValueError(f"refusing unsafe backup entry: {info.name}")
    return info


def add_tree(archive: tarfile.TarFile) -> None:
    for path in sorted(ROOT.rglob("*")):
        if not include_path(path):
            continue
        relative = path.relative_to(ROOT)
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"refusing unsafe backup entry: {relative}")
        archive.add(
            path,
            arcname=Path("lyta-shield") / relative,
            recursive=False,
            filter=safe_archive_filter,
        )


def main() -> int:
    if not PRIVATE_KEY.exists() or not PUBLIC_KEY.exists():
        raise SystemExit("missing signing keypair; run scripts/generate-backup-key.py")
    private_info = PRIVATE_KEY.lstat()
    if not stat.S_ISREG(private_info.st_mode) or private_info.st_nlink != 1:
        raise SystemExit("private signing key must be one regular file")
    if stat.S_IMODE(private_info.st_mode) != 0o600:
        raise SystemExit("private signing key permissions must be 0600")

    signing_key = SigningKey(read_regular_file(PRIVATE_KEY, 32))
    public_key = read_regular_file(PUBLIC_KEY, 32)
    if signing_key.verify_key.encode() != public_key:
        raise SystemExit("public and private signing keys do not match")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    archive_path = BACKUP_DIR / f"lyta-shield-{stamp}.tar.gz"
    try:
        with tarfile.open(archive_path, "x:gz") as archive:
            add_tree(archive)
    except (OSError, ValueError) as error:
        archive_path.unlink(missing_ok=True)
        raise SystemExit(str(error)) from error
    os.chmod(archive_path, 0o600)

    digest = sha256_regular_file(archive_path)
    manifest = {
        "version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "archive": archive_path.name,
        "sha256": digest,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": ".",
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
    }
    manifest["signature"] = base64.b64encode(
        signing_key.sign(canonical_message(manifest)).signature
    ).decode("ascii")

    manifest_path = archive_path.with_suffix(archive_path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    print(archive_path)
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
