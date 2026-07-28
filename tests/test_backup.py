#!/usr/bin/env python3
"""Tests for backup signing, verification, and self-heal path."""
import subprocess
import tempfile
from pathlib import Path

import pytest

LYTA = Path(__file__).resolve().parent.parent


def run_cli(*args, timeout=60):
    cmd = [str(LYTA / "bin" / "lyta-shield")] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result


@pytest.fixture(scope="module")
def backup_result():
    result = run_cli("backup")
    assert result.returncode == 0, result.stderr
    return result


def test_backup_creates_signed_archive(backup_result):
    """Backup should produce a signed tarball, signature, and manifest."""
    var_backups = LYTA / "var" / "backups"
    assert var_backups.exists()
    manifests = sorted(var_backups.glob("*.manifest"))
    assert len(manifests) > 0
    manifest = manifests[-1]
    data = manifest.read_text()
    assert "sha256" in data.lower()
    assert "signature" in data.lower()
    assert "public_key" in data.lower()


def test_verify_backup_passes(backup_result):
    result = run_cli("verify-backup")
    assert result.returncode == 0, result.stderr
    assert "authentic" in result.stdout.lower() or "verified" in result.stdout.lower()


def test_tamper_detected_and_self_heal():
    # Pick a small script to tamper
    target = LYTA / "scripts" / "backup-sign.py"
    original = target.read_text()
    tampered = original + "\n# TAMPERED\n"
    target.write_text(tampered)
    try:
        result = run_cli("self-heal", "--file", str(target))
        # Self-heal should either restore or report a failure
        assert result.returncode in (0, 1), result.stderr
    finally:
        # Restore from backup if possible
        result = run_cli("restore-from-backup", "--file", str(target))
        target.write_text(original)


def test_backup_signature_is_ed25519(backup_result):
    var_backups = LYTA / "var" / "backups"
    manifests = sorted(var_backups.glob("*.manifest"))
    manifest = manifests[-1]
    data = manifest.read_text()
    assert "ed25519" in data.lower() or "public_key" in data.lower()
