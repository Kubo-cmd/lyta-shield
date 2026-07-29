#!/usr/bin/env python3
"""Offline-first bridge between LYTA Shield and Codex Security.

The bridge never installs packages or starts a paid scan. It can:
- verify local prerequisites,
- build and optionally execute Codex Security's network-free dry run,
- normalize an existing SARIF report into a compact LYTA Shield document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

UPSTREAM_REPOSITORY = "https://github.com/openai/codex-security"
UPSTREAM_COMMIT = "f22d4a36f26d16287bcdfd707b369116e02a08c3"
UPSTREAM_PACKAGE_VERSION = "0.1.1"
UPSTREAM_PLUGIN_VERSION = "0.1.14"
UPSTREAM_NPM_INTEGRITY = "sha512-sNxULf7IyicJRgYnycguaEzO2ZeANEv3oyrupjMoKVq5TjRrmIhORpaa7U2LVIpEHJP7//icGZV37MRIlp9X/A=="
UPSTREAM_CLI_SHA256 = "8464effc0af5c05c2d58703de9f43c315b0c9e4e66299937c5cf8a304294e326"
MAX_SARIF_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 100_000
MAX_MESSAGE_CHARS = 4_096
SEVERITIES = ("critical", "high", "medium", "low", "informational", "unknown")
SARIF_LEVELS = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for item in value.removeprefix("v").split("."):
        digits = "".join(character for character in item if character.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _command_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = (result.stdout or result.stderr).strip().splitlines()
    return value[0] if result.returncode == 0 and value else None


def _secret_stripped_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not any(marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))
    }


def _regular_file_record(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            raise ValueError(f"File ownership or permissions are unsafe: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return {
            "type": "file",
            "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def _sha256_file(path: Path) -> str:
    return str(_regular_file_record(path)["sha256"])


def _read_safe_regular_text(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_size > max_bytes
        ):
            raise ValueError(f"File ownership, permissions, or size are unsafe: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1))
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > max_bytes:
                raise ValueError(f"File is too large: {path}")
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(descriptor)


def _runtime_root(executable: Path) -> Path | None:
    for parent in executable.parents:
        if parent.name == "node_modules":
            return parent
    return None


def _runtime_entries(root: Path) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    root = root.resolve()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        names = list(files)
        for directory in list(directories):
            candidate = current_path / directory
            if candidate.is_symlink():
                directories.remove(directory)
                names.append(directory)
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
                resolved_target = (path.parent / target).resolve()
                try:
                    resolved_target.relative_to(root)
                except ValueError as error:
                    raise ValueError(f"Runtime symlink escapes dependency tree: {relative}") from error
                if not resolved_target.exists():
                    raise ValueError(f"Runtime symlink is broken: {relative}")
                entries[relative] = {"type": "symlink", "target": target}
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"Runtime entry is not a regular file: {relative}")
            entries[relative] = _regular_file_record(path)
    return dict(sorted(entries.items()))


def build_runtime_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    package_lock = root.parent / "package-lock.json"
    if not package_lock.is_file():
        raise ValueError("Codex Security runtime package-lock.json is missing")
    return {
        "version": 1,
        "platform": {"system": platform.system().lower(), "machine": platform.machine().lower()},
        "package_lock_sha256": _sha256_file(package_lock),
        "entries": _runtime_entries(root),
    }


def write_runtime_manifest(root: Path, output: Path) -> None:
    document = build_runtime_manifest(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def _runtime_tree_trusted(executable: Path) -> bool:
    root = _runtime_root(executable)
    if root is None:
        return True
    configured = os.environ.get("CODEX_SECURITY_RUNTIME_MANIFEST")
    manifest = (
        Path(configured).expanduser()
        if configured
        else root.parent / f"runtime-integrity-{platform.system().lower()}-{platform.machine().lower()}.json"
    )
    try:
        expected = json.loads(_read_safe_regular_text(manifest))
        current = build_runtime_manifest(root)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    return expected == current


def resolve_python() -> str | None:
    configured = os.environ.get("CODEX_SECURITY_PYTHON")
    names = [configured] if configured else ["python3.12", "python3.11", "python3.10"]
    if sys.version_info >= (3, 10):
        names.append(sys.executable)
    for name in names:
        if not name:
            continue
        candidate = shutil.which(name) if not Path(name).is_absolute() else name
        if not candidate:
            continue
        version = _command_version([candidate, "--version"])
        if version and _version_tuple(version.split()[-1]) >= (3, 10):
            return str(Path(candidate).resolve())
    return None


def _trusted_executable(path: str | Path) -> Path | None:
    expected = os.environ.get("CODEX_SECURITY_SHA256", UPSTREAM_CLI_SHA256).lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        return None
    candidate = Path(path).expanduser()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    resolved = candidate.resolve()
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            os.close(descriptor)
            return None
        with os.fdopen(descriptor, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    if digest.hexdigest() != expected or not _runtime_tree_trusted(resolved):
        return None
    return resolved


def resolve_codex_security(repository: Path | None = None) -> str | None:
    configured = os.environ.get("CODEX_SECURITY_BIN")
    if configured:
        candidate = _trusted_executable(configured)
        return str(candidate) if candidate else None

    installed = shutil.which("codex-security")
    if installed:
        candidate = _trusted_executable(installed)
        if candidate:
            return str(candidate)

    if repository is not None:
        candidates = (
            repository / "integrations" / "codex-security-runtime" / "node_modules" / ".bin" / "codex-security",
            repository / "node_modules" / ".bin" / "codex-security",
        )
        for candidate in candidates:
            trusted = _trusted_executable(candidate)
            if trusted:
                return str(trusted)
    return None


def doctor(repository: Path | None = None) -> dict[str, Any]:
    node_version = _command_version(["node", "--version"])
    python = resolve_python()
    python_version = _command_version([python, "--version"]) if python else None
    cli = resolve_codex_security(repository)
    cli_version = _command_version([cli, "--version"]) if cli else None
    checks = {
        "node_22_or_later": bool(node_version and _version_tuple(node_version) >= (22,)),
        "python_3_10_or_later": python is not None,
        "codex_security_installed": cli is not None,
        "codex_security_digest_pinned": cli is not None,
        "codex_security_runtime_tree_pinned": cli is not None,
        "codex_security_exact_version": cli_version == UPSTREAM_PACKAGE_VERSION,
    }
    return {
        "ready": all(checks.values()),
        "checks": checks,
        "node_version": node_version,
        "python_version": python_version,
        "python_binary": python,
        "codex_security_binary": cli,
        "codex_security_version": cli_version,
        "upstream": {
            "repository": UPSTREAM_REPOSITORY,
            "commit": UPSTREAM_COMMIT,
            "package_version": UPSTREAM_PACKAGE_VERSION,
            "plugin_version": UPSTREAM_PLUGIN_VERSION,
            "npm_integrity": UPSTREAM_NPM_INTEGRITY,
        },
        "policy": "offline-first; dry-run only; no automatic install; no paid scan",
    }


def build_dry_run_command(
    executable: str,
    repository: Path,
    output_dir: Path,
    *,
    diff: str | None = None,
    working_tree: bool = False,
    paths: list[str] | None = None,
    python_executable: str | None = None,
) -> list[str]:
    selectors = int(bool(diff)) + int(working_tree) + int(bool(paths))
    if selectors != 1:
        raise ValueError("Exactly one explicit scan scope is required: --path, --diff, or --working-tree")
    repository_root = repository.resolve()
    if not repository_root.is_dir():
        raise ValueError("Scanned repository must be an existing directory")
    if output_dir.is_symlink():
        raise ValueError("Output directory must not be a symlink")
    output_root = output_dir.resolve()
    try:
        inside_repository = os.path.commonpath([repository_root, output_root]) == str(repository_root)
    except ValueError:
        inside_repository = False
    if inside_repository:
        raise ValueError("Output directory must be outside the scanned repository")
    if diff and (len(diff) > 512 or diff.startswith("-") or any(ord(character) < 32 for character in diff)):
        raise ValueError("Invalid diff revision")
    for requested in paths or []:
        relative = Path(requested)
        if relative.is_absolute() or ".." in relative.parts or not requested:
            raise ValueError("Scan paths must be non-empty repository-relative paths")
        target = (repository_root / relative).resolve()
        if os.path.commonpath([repository_root, target]) != str(repository_root) or not target.exists():
            raise ValueError("Scan paths must exist inside the repository")
    python = python_executable or resolve_python()
    python_version = _command_version([python, "--version"]) if python else None
    if not python or not python_version or _version_tuple(python_version.split()[-1]) < (3, 10):
        raise ValueError("Python 3.10 or later is required")
    command = [
        executable,
        "scan",
        str(repository.resolve()),
        "--output-dir",
        str(output_dir.resolve()),
        "--dry-run",
        "--json",
        "--auth",
        "chatgpt",
        "--python",
        str(Path(python).resolve()),
    ]
    if diff:
        command.extend(["--diff", diff])
    if working_tree:
        command.append("--working-tree")
    for path in paths or []:
        command.extend(["--path", path])
    return command


def run_dry_run(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute only a command produced by build_dry_run_command."""
    if len(command) < 12:
        raise ValueError("Refusing unexpected Codex Security executable")
    trusted = _trusted_executable(command[0])
    if trusted is None:
        raise ValueError("Refusing unpinned or digest-mismatched Codex Security executable")
    command = [str(trusted), *command[1:]]
    try:
        repository = Path(command[2])
        output_dir = Path(command[command.index("--output-dir") + 1])
        auth = command[command.index("--auth") + 1]
        python = command[command.index("--python") + 1]
    except (ValueError, IndexError) as error:
        raise ValueError("Dry run requires repository, output, auth, and Python fields") from error
    diff = command[command.index("--diff") + 1] if "--diff" in command else None
    working_tree = "--working-tree" in command
    paths = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "--path"]
    if auth != "chatgpt":
        raise ValueError("Dry run requires chatgpt authentication")
    expected = build_dry_run_command(
        str(trusted),
        repository,
        output_dir,
        diff=diff,
        working_tree=working_tree,
        paths=paths,
        python_executable=python,
    )
    if command != expected:
        raise ValueError("Refusing non-canonical Codex Security command")
    if output_dir.exists() and (output_dir.is_symlink() or not output_dir.is_dir()):
        raise ValueError("Output directory must be a regular directory")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = output_dir.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError("Output directory must be owner-only (mode 0700)")
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=_secret_stripped_environment(),
    )


def _rule_metadata(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    driver = run.get("tool", {}).get("driver", {})
    for rule in driver.get("rules", []) or []:
        if isinstance(rule, dict) and rule.get("id"):
            rules[str(rule["id"])] = rule
    return rules


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    properties = result.get("properties", {})
    rule_properties = rule.get("properties", {})
    candidates = (
        properties.get("security-severity"),
        properties.get("severity"),
        rule_properties.get("security-severity"),
        rule_properties.get("severity"),
    )
    for candidate in candidates:
        value = str(candidate or "").lower()
        if value in SEVERITIES:
            return value
        try:
            score = float(value)
        except ValueError:
            continue
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    return SARIF_LEVELS.get(str(result.get("level", "")).lower(), "unknown")


def _location(result: dict[str, Any]) -> tuple[str | None, int | None]:
    locations = result.get("locations") or []
    if not locations or not isinstance(locations[0], dict):
        return None, None
    physical = locations[0].get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    path = artifact.get("uri")
    line = region.get("startLine")
    return (str(path) if path else None, int(line) if isinstance(line, int) else None)


def normalize_sarif(document: dict[str, Any], source: Path) -> dict[str, Any]:
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("Expected a SARIF 2.1.0 document with a runs array")

    findings: list[dict[str, Any]] = []
    for run in document["runs"]:
        if not isinstance(run, dict):
            continue
        rules = _rule_metadata(run)
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            if len(findings) >= MAX_FINDINGS:
                raise ValueError(f"SARIF contains more than {MAX_FINDINGS} findings")
            rule_id = str(result.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            message_data = result.get("message", {})
            message = message_data.get("text") if isinstance(message_data, dict) else str(message_data)
            message = str(message or "")[:MAX_MESSAGE_CHARS]
            path, line = _location(result)
            title = rule.get("shortDescription", {}).get("text") or rule_id
            partial = result.get("partialFingerprints") or {}
            fingerprint = next(iter(partial.values()), None) if isinstance(partial, dict) else None
            if not fingerprint:
                material = f"{rule_id}\0{path}\0{line}\0{message}".encode("utf-8")
                fingerprint = hashlib.sha256(material).hexdigest()[:24]
            findings.append(
                {
                    "id": rule_id,
                    "title": str(title),
                    "severity": _severity(result, rule),
                    "message": message,
                    "path": path,
                    "line": line,
                    "fingerprint": str(fingerprint),
                }
            )

    findings.sort(key=lambda item: (item["path"] or "", item["line"] or 0, item["id"]))
    counts = Counter(item["severity"] for item in findings)
    return {
        "schema_version": 1,
        "source": "codex-security-sarif",
        "source_file": source.name,
        "upstream_commit": UPSTREAM_COMMIT,
        "summary": {"total": len(findings), **{name: counts[name] for name in SEVERITIES}},
        "findings": findings,
        "learning_policy": "review findings before adding rules; never auto-train or auto-block",
    }


def load_sarif(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("SARIF input must be a regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            os.close(descriptor)
            raise ValueError("SARIF input must be an owner-controlled regular file")
        if metadata.st_size > MAX_SARIF_BYTES:
            os.close(descriptor)
            raise ValueError("SARIF input exceeds 32 MiB")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to read SARIF: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("SARIF root must be an object")
    return normalize_sarif(document, path)


def write_private_output(path: Path, content: str) -> None:
    """Write output without following a caller-controlled final symlink."""
    if path.parent.is_symlink():
        raise ValueError("Output directory must not be a symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_metadata = path.parent.stat()
    if parent_metadata.st_uid != os.getuid() or parent_metadata.st_mode & 0o077:
        raise ValueError("Output directory must be owner-only (mode 0700)")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Output path must be a regular file")
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            os.close(descriptor)
            raise ValueError("Output path must be an owner-controlled regular file")
        os.ftruncate(descriptor, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    except OSError as error:
        raise ValueError(f"Unable to write output: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check local prerequisites without network access")
    doctor_parser.add_argument("repository", nargs="?", type=Path)

    preflight = subparsers.add_parser("preflight", help="Run Codex Security's network-free dry run")
    preflight.add_argument("repository", type=Path)
    preflight.add_argument("--output-dir", required=True, type=Path)
    target = preflight.add_mutually_exclusive_group()
    target.add_argument("--diff")
    target.add_argument("--working-tree", action="store_true")
    preflight.add_argument("--path", action="append", default=[])

    ingest = subparsers.add_parser("ingest-sarif", help="Normalize an existing SARIF report offline")
    ingest.add_argument("sarif", type=Path)
    ingest.add_argument("--output", type=Path)

    args = parser.parse_args()
    if args.command == "doctor":
        result = doctor(args.repository)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ready"] else 2

    if args.command == "preflight":
        executable = resolve_codex_security(args.repository)
        if not executable:
            print(json.dumps({"error": "codex-security is not installed; no package was downloaded"}))
            return 2
        try:
            command = build_dry_run_command(
                executable,
                args.repository,
                args.output_dir,
                diff=args.diff,
                working_tree=args.working_tree,
                paths=args.path,
            )
            result = run_dry_run(command)
        except ValueError as error:
            print(json.dumps({"error": str(error)}))
            return 2
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        return result.returncode

    try:
        normalized = load_sarif(args.sarif)
    except ValueError as error:
        print(json.dumps({"error": str(error)}))
        return 2
    output = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    if args.output:
        try:
            write_private_output(args.output, output)
        except ValueError as error:
            print(json.dumps({"error": str(error)}))
            return 2
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
