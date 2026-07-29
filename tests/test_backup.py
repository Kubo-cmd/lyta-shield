import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from nacl.signing import SigningKey, VerifyKey

from scripts.backup_common import ALGORITHM, SCHEMA_VERSION, canonical_message

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "lyta-shield"


def run_cli(*args, env=None, cli=CLI, cwd=ROOT):
    runtime_env = (env or os.environ).copy()
    runtime_env["PATH"] = os.pathsep.join((str(Path(sys.executable).parent), runtime_env.get("PATH", "")))
    runtime_env["PYTHONPATH"] = os.pathsep.join(str(path) for path in sys.path if path)
    return subprocess.run([str(cli), *args], text=True, capture_output=True, env=runtime_env, cwd=cwd)


def isolated_key_scripts(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    scripts = tmp_path / "repo" / "scripts"
    scripts.mkdir(parents=True)
    for name in ("backup_common.py", "generate-backup-key.py", "rotate-backup-key.py"):
        shutil.copy2(ROOT / "scripts" / name, scripts / name)
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in sys.path)
    env.pop("LYTA_BACKUP_PUBLIC_KEY", None)
    return scripts, env


@pytest.fixture(scope="module")
def backup_result(tmp_path_factory):
    sandbox = tmp_path_factory.mktemp("backup-repo") / "repo"
    shutil.copytree(
        ROOT,
        sandbox,
        ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", "dist", "backups", "keys"),
    )
    home = sandbox.parent / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in sys.path)
    env.pop("LYTA_BACKUP_PUBLIC_KEY", None)
    ignored_bin = sandbox / "integrations" / "synthetic" / "node_modules" / ".bin"
    ignored_bin.mkdir(parents=True, exist_ok=True)
    (ignored_bin / "scanner").symlink_to("/tmp/not-part-of-backup")
    generate = subprocess.run(
        [sys.executable, str(sandbox / "scripts" / "generate-backup-key.py")],
        text=True,
        capture_output=True,
        env=env,
        cwd=sandbox,
    )
    assert generate.returncode == 0, generate.stderr
    cli = sandbox / "bin" / "lyta-shield"
    result = run_cli("backup", env=env, cli=cli, cwd=sandbox)
    assert result.returncode == 0, result.stderr
    lines = [Path(line) for line in result.stdout.splitlines() if line.strip()]
    archive, manifest = lines[-2:]
    yield {
        "archive": archive,
        "manifest": manifest,
        "public_key": sandbox / "var" / "keys" / "backup-sign.nacl.pub",
        "cli": cli,
        "cwd": sandbox,
        "env": env,
    }


def test_backup_creates_signed_archive(backup_result):
    archive = backup_result["archive"]
    manifest_path = backup_result["manifest"]
    manifest = json.loads(manifest_path.read_text())
    assert archive.exists()
    assert manifest_path.exists()
    assert manifest["version"] == SCHEMA_VERSION
    assert manifest["algorithm"] == ALGORITHM
    assert manifest["archive"] == archive.name
    assert manifest["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert "public_key" not in manifest
    assert "sign_message" not in manifest
    assert manifest["source"] == "."
    assert os.stat(archive).st_mode & 0o077 == 0
    with tarfile.open(archive, "r:gz") as bundle:
        assert all("node_modules" not in Path(name).parts for name in bundle.getnames())


def test_verify_backup_passes(backup_result):
    manifest = backup_result["manifest"]
    result = run_cli(
        "verify-backup",
        str(manifest),
        env=backup_result["env"],
        cli=backup_result["cli"],
        cwd=backup_result["cwd"],
    )
    assert result.returncode == 0, result.stderr
    assert "[OK] backup verified" in result.stdout


def test_backup_signature_is_ed25519(backup_result):
    manifest_path = backup_result["manifest"]
    manifest = json.loads(manifest_path.read_text())
    public_key = backup_result["public_key"].read_bytes()
    VerifyKey(public_key).verify(
        canonical_message(manifest),
        base64.b64decode(manifest["signature"], validate=True),
    )


def test_manifest_path_traversal_is_rejected(tmp_path):
    manifest = {
        "version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "archive": "../escape.tar.gz",
        "sha256": "0" * 64,
        "signature": base64.b64encode(b"x" * 64).decode(),
        "public_key_fingerprint": "0" * 64,
    }
    path = tmp_path / "bad.tar.gz.manifest.json"
    path.write_text(json.dumps(manifest))
    result = run_cli("verify-backup", str(path))
    assert result.returncode == 1
    assert "must be a basename" in result.stderr


def test_backup_refuses_symlinks_and_removes_partial_archive(tmp_path):
    sandbox = tmp_path / "repo"
    shutil.copytree(
        ROOT,
        sandbox,
        ignore=shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", "dist", "backups", "keys"),
    )
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in sys.path if path)
    env.pop("LYTA_BACKUP_PUBLIC_KEY", None)
    generate = subprocess.run(
        [sys.executable, str(sandbox / "scripts" / "generate-backup-key.py")],
        text=True,
        capture_output=True,
        env=env,
        cwd=sandbox,
    )
    assert generate.returncode == 0, generate.stderr
    outside = tmp_path / "outside.txt"
    outside.write_text("must not enter archive", encoding="utf-8")
    (sandbox / "unsafe-link").symlink_to(outside)

    result = run_cli("backup", env=env, cli=sandbox / "bin" / "lyta-shield", cwd=sandbox)

    assert result.returncode != 0
    assert "refusing unsafe backup entry" in result.stderr
    assert not list((sandbox / "var" / "backups").glob("*.tar.gz"))


def test_attacker_supplied_key_cannot_forge_backup(tmp_path, backup_result):
    archive = backup_result["archive"]
    forged_archive = tmp_path / archive.name
    forged_archive.write_bytes(b"forged")
    attacker = SigningKey.generate()
    manifest = {
        "version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "archive": forged_archive.name,
        "sha256": hashlib.sha256(forged_archive.read_bytes()).hexdigest(),
        "created_utc": "1970-01-01T00:00:00+00:00",
        "source": ".",
        "public_key_fingerprint": hashlib.sha256(attacker.verify_key.encode()).hexdigest(),
    }
    manifest["signature"] = base64.b64encode(
        attacker.sign(canonical_message(manifest)).signature
    ).decode()
    path = tmp_path / "forged.tar.gz.manifest.json"
    path.write_text(json.dumps(manifest))
    result = run_cli(
        "verify-backup",
        str(path),
        env=backup_result["env"],
        cli=backup_result["cli"],
        cwd=backup_result["cwd"],
    )
    assert result.returncode == 1
    assert "signature verification failed" in result.stderr


def test_key_generation_is_umask_independent_and_creates_external_trust(tmp_path):
    scripts, env = isolated_key_scripts(tmp_path)
    result = subprocess.run(
        [sys.executable, str(scripts / "generate-backup-key.py")],
        text=True,
        capture_output=True,
        env=env,
        preexec_fn=lambda: os.umask(0),
    )
    assert result.returncode == 0, result.stderr
    private = scripts.parent / "var" / "keys" / "backup-sign.nacl"
    public = private.with_suffix(".nacl.pub")
    trust = Path(env["HOME"]) / ".config" / "lyta-shield" / "trusted-backup.pub"
    assert private.stat().st_mode & 0o777 == 0o600
    assert private.parent.stat().st_mode & 0o777 == 0o700
    assert SigningKey(private.read_bytes()).verify_key.encode() == public.read_bytes()
    assert trust.read_bytes() == public.read_bytes()


def test_key_generation_refuses_partial_or_symlinked_keypair(tmp_path):
    scripts, env = isolated_key_scripts(tmp_path)
    keys = scripts.parent / "var" / "keys"
    keys.mkdir(parents=True)
    outside = tmp_path / "outside-key"
    outside.write_bytes(b"unchanged")
    (keys / "backup-sign.nacl").symlink_to(outside)
    (keys / "backup-sign.nacl.pub").write_bytes(b"x" * 32)
    result = subprocess.run(
        [sys.executable, str(scripts / "generate-backup-key.py")],
        text=True,
        capture_output=True,
        env=env,
    )
    assert result.returncode != 0
    assert outside.read_bytes() == b"unchanged"


def test_rotation_updates_keypair_and_external_trust_with_safe_modes(tmp_path):
    scripts, env = isolated_key_scripts(tmp_path)
    generate = subprocess.run(
        [sys.executable, str(scripts / "generate-backup-key.py")],
        text=True,
        capture_output=True,
        env=env,
    )
    assert generate.returncode == 0, generate.stderr
    private = scripts.parent / "var" / "keys" / "backup-sign.nacl"
    public = private.with_suffix(".nacl.pub")
    trust = Path(env["HOME"]) / ".config" / "lyta-shield" / "trusted-backup.pub"
    previous = private.read_bytes()
    result = subprocess.run(
        [sys.executable, str(scripts / "rotate-backup-key.py")],
        text=True,
        capture_output=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert private.read_bytes() != previous
    assert private.stat().st_mode & 0o777 == 0o600
    assert SigningKey(private.read_bytes()).verify_key.encode() == public.read_bytes()
    assert trust.read_bytes() == public.read_bytes()
