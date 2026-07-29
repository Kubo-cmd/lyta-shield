#!/usr/bin/env python3
"""Create, verify, and safely restore the LYTA Shield integrity baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

try:
    from .backup_common import verify_manifest
except ImportError:  # Direct script execution.
    from backup_common import verify_manifest

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "var" / "integrity-baseline.json"
BACKUP_DIR = ROOT / "var" / "backups"
MAX_PROTECTED_FILE_BYTES = 8 * 1024 * 1024
EXPECTED = (
    "src/rules_engine.py",
    "src/rules.json",
    "bin/lyta-shield",
    "bin/lyta-shield-doctor",
    "integrations/codex_security_bridge.py",
    "integrations/hermes_guard.py",
    "integrations/hermes-chat-audit.py",
    "integrations/hermes-wrapper.sh",
    "extensions/browser/lyta_shield_console_guard.user.js",
    "scripts/backup_common.py",
    "scripts/backup-key-health.py",
    "scripts/backup-sign.py",
    "scripts/export-metrics.py",
    "scripts/generate-backup-key.py",
    "scripts/integrity.py",
    "scripts/install-wrapper.py",
    "scripts/rotate-backup-key.py",
    "scripts/rotate-backups.py",
    "scripts/verify-backup.py",
)


def target_path(relative: str, root: Path = ROOT) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("protected path must be relative")
    normalized = Path(relative)
    if ".." in normalized.parts or normalized.as_posix() != relative:
        raise ValueError("protected path is not canonical")
    root = root.resolve(strict=True)
    target = root / normalized
    resolved_parent = target.parent.resolve(strict=True)
    if resolved_parent != root and root not in resolved_parent.parents:
        raise ValueError("protected path escapes repository")
    return target


def read_regular_file(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError(f"symlink is not allowed: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular file: {path}")
        if info.st_size > MAX_PROTECTED_FILE_BYTES:
            raise ValueError(f"protected file exceeds size limit: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_baseline(path: Path = BASELINE) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 2 or not isinstance(data.get("files"), dict):
        raise ValueError("unsupported integrity baseline; recreate it")
    files: dict[str, str] = data["files"]
    for relative, digest in files.items():
        try:
            target_path(relative)
        except ValueError as error:
            raise ValueError(f"unsafe baseline path: {relative}") from error
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"invalid baseline digest: {relative}")
    if set(files) != set(EXPECTED):
        raise ValueError("integrity baseline file set is incomplete or unexpected")
    return files


def create_baseline() -> int:
    files: dict[str, str] = {}
    for relative in EXPECTED:
        files[relative] = digest_bytes(read_regular_file(target_path(relative)))
    BASELINE.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"version": 2, "files": files}, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".integrity-", dir=BASELINE.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, BASELINE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"[OK] integrity baseline written: {BASELINE}")
    return 0


def verify_baseline(quiet: bool = False) -> int:
    try:
        files = load_baseline()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[FAIL] integrity baseline: {error}")
        return 1
    failures = []
    for relative, expected in files.items():
        try:
            actual = digest_bytes(read_regular_file(target_path(relative)))
        except (OSError, ValueError) as error:
            failures.append(f"{relative}: {error}")
            continue
        if actual != expected:
            failures.append(f"{relative}: digest mismatch")
    if failures:
        print("[FAIL] integrity verification:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    if not quiet:
        print(f"[OK] integrity verified ({len(files)} protected files)")
    return 0


def backup_bytes(relative: str, expected: str) -> tuple[bytes, int] | None:
    if not BACKUP_DIR.exists():
        return None
    manifests = sorted(BACKUP_DIR.glob("*.manifest.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    member_name = f"lyta-shield/{relative}"
    for manifest_path in manifests:
        try:
            archive_path, _ = verify_manifest(manifest_path)
            with tarfile.open(archive_path, "r:gz") as archive:
                member = archive.getmember(member_name)
                if not member.isfile() or member.size > MAX_PROTECTED_FILE_BYTES:
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                data = stream.read(MAX_PROTECTED_FILE_BYTES + 1)
                if len(data) > MAX_PROTECTED_FILE_BYTES or digest_bytes(data) != expected:
                    continue
                return data, member.mode & 0o777
        except (OSError, ValueError, KeyError, tarfile.TarError):
            continue
    return None


def git_bytes(relative: str, expected: str) -> tuple[bytes, int] | None:
    try:
        data = subprocess.run(
            ["git", "show", f"HEAD:{relative}"], cwd=ROOT, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout
        if len(data) > MAX_PROTECTED_FILE_BYTES or digest_bytes(data) != expected:
            return None
        mode_text = subprocess.run(
            ["git", "ls-tree", "HEAD", "--", relative], cwd=ROOT, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        ).stdout.split()[0]
        mode = 0o755 if mode_text == "100755" else 0o644
        return data, mode
    except (OSError, subprocess.CalledProcessError, IndexError):
        return None


def atomic_restore(relative: str, data: bytes, mode: int) -> None:
    target = target_path(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode & 0o777)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def normalize_requested(values: list[str]) -> list[str]:
    if not values:
        return list(EXPECTED)
    result = []
    for value in values:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve(strict=False).relative_to(ROOT).as_posix()
            except ValueError as error:
                raise ValueError(f"target outside repository: {value}") from error
        else:
            relative = candidate.as_posix()
        if relative not in EXPECTED:
            raise ValueError(f"target is not protected: {relative}")
        if relative not in result:
            result.append(relative)
    return result


def heal(values: list[str]) -> int:
    try:
        baseline = load_baseline()
        requested = normalize_requested(values)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[FAIL] self-heal: {error}")
        return 1

    failed = False
    for relative in requested:
        expected = baseline[relative]
        try:
            current = digest_bytes(read_regular_file(target_path(relative)))
        except (OSError, ValueError):
            current = None
        if current == expected:
            print(f"[OK] {relative}")
            continue
        source = backup_bytes(relative, expected) or git_bytes(relative, expected)
        if source is None:
            print(f"[FAIL] no trusted recovery source matches baseline: {relative}")
            failed = True
            continue
        data, mode = source
        atomic_restore(relative, data, mode)
        if digest_bytes(read_regular_file(target_path(relative))) != expected:
            print(f"[FAIL] post-restore verification failed: {relative}")
            failed = True
            continue
        print(f"[HEALED] {relative}")
    return 1 if failed else verify_baseline(quiet=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("create")
    subparsers.add_parser("verify")
    heal_parser = subparsers.add_parser("heal")
    heal_parser.add_argument("targets", nargs="*")
    args = parser.parse_args()
    if args.command == "create":
        return create_baseline()
    if args.command == "verify":
        return verify_baseline()
    return heal(args.targets)


if __name__ == "__main__":
    sys.exit(main())
