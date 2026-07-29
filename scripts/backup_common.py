#!/usr/bin/env python3
"""Shared, fail-closed backup verification helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

SCHEMA_VERSION = 2
ALGORITHM = "ed25519-sha256"
MAX_MANIFEST_BYTES = 64 * 1024


def read_regular_file(path: Path, max_bytes: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"symlink is not allowed: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular file: {path.name}")
        if info.st_size > max_bytes:
            raise ValueError(f"file exceeds size limit: {path.name}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def sha256_regular_file(path: Path) -> str:
    if path.is_symlink():
        raise ValueError(f"symlink is not allowed: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"not a regular file: {path.name}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def trusted_public_key_path() -> Path:
    override = os.environ.get("LYTA_BACKUP_PUBLIC_KEY")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".config" / "lyta-shield" / "trusted-backup.pub"


def safe_basename(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ValueError(f"invalid {field}")
    if Path(value).name != value or "/" in value or "\\" in value:
        raise ValueError(f"{field} must be a basename")
    return value


def canonical_message(manifest: dict[str, Any]) -> bytes:
    if manifest.get("version") != SCHEMA_VERSION:
        raise ValueError("unsupported manifest version")
    if manifest.get("algorithm") != ALGORITHM:
        raise ValueError("unsupported signature algorithm")
    archive = safe_basename(manifest.get("archive"), "archive")
    digest = manifest.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("invalid sha256")
    try:
        bytes.fromhex(digest)
    except ValueError as error:
        raise ValueError("invalid sha256") from error
    return f"lyta-shield-backup-v2\n{archive}\n{digest}\n".encode("ascii")


def read_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(read_regular_file(path, MAX_MANIFEST_BYTES).decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be an object")
    safe_basename(path.name, "manifest")
    if not path.name.endswith(".tar.gz.manifest.json"):
        raise ValueError("manifest filename must end with .tar.gz.manifest.json")
    canonical_message(data)
    signature_text = data.get("signature")
    if not isinstance(signature_text, str):
        raise ValueError("missing signature")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except ValueError as error:
        raise ValueError("invalid signature encoding") from error
    if len(signature) != 64:
        raise ValueError("invalid signature length")
    fingerprint = data.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError("invalid public key fingerprint")
    try:
        bytes.fromhex(fingerprint)
    except ValueError as error:
        raise ValueError("invalid public key fingerprint") from error
    return data


def verify_manifest(path: Path, trusted_key: Path | None = None) -> tuple[Path, dict[str, Any]]:
    if path.is_symlink():
        raise ValueError("manifest symlink is not allowed")
    manifest_path = path.resolve(strict=True)
    manifest = read_manifest(manifest_path)
    archive_candidate = manifest_path.parent / safe_basename(manifest["archive"], "archive")
    if archive_candidate.is_symlink():
        raise ValueError("archive symlink is not allowed")
    archive = archive_candidate.resolve(strict=True)
    if archive.parent != manifest_path.parent:
        raise ValueError("archive escapes manifest directory")
    digest = sha256_regular_file(archive)
    if digest != manifest.get("sha256"):
        raise ValueError("archive sha256 mismatch")

    key_candidate = trusted_key or trusted_public_key_path()
    if key_candidate.is_symlink():
        raise ValueError("trusted public key symlink is not allowed")
    key_path = key_candidate.resolve(strict=True)
    key_bytes = read_regular_file(key_path, 32)
    if len(key_bytes) != 32:
        raise ValueError("trusted public key has invalid length")
    signature_text = manifest.get("signature")
    if not isinstance(signature_text, str):
        raise ValueError("missing signature")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        VerifyKey(key_bytes).verify(canonical_message(manifest), signature)
    except (ValueError, BadSignatureError) as error:
        raise ValueError("signature verification failed") from error

    fingerprint = hashlib.sha256(key_bytes).hexdigest()
    if manifest.get("public_key_fingerprint") != fingerprint:
        raise ValueError("trusted public key fingerprint mismatch")
    return archive, manifest
