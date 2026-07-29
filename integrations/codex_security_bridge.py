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
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

UPSTREAM_REPOSITORY = "https://github.com/openai/codex-security"
UPSTREAM_COMMIT = "f22d4a36f26d16287bcdfd707b369116e02a08c3"
UPSTREAM_PACKAGE_VERSION = "0.1.1"
UPSTREAM_PLUGIN_VERSION = "0.1.14"
UPSTREAM_NPM_INTEGRITY = "sha512-sNxULf7IyicJRgYnycguaEzO2ZeANEv3oyrupjMoKVq5TjRrmIhORpaa7U2LVIpEHJP7//icGZV37MRIlp9X/A=="
MAX_SARIF_BYTES = 32 * 1024 * 1024
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


def _trusted_executable(path: str | Path) -> Path | None:
    expected = os.environ.get("CODEX_SECURITY_SHA256", "").lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        return None
    candidate = Path(path).expanduser()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    resolved = candidate.resolve()
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return resolved if digest.hexdigest() == expected else None


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
        candidate = repository / "node_modules" / ".bin" / "codex-security"
        trusted = _trusted_executable(candidate)
        if trusted:
            return str(trusted)
    return None


def doctor(repository: Path | None = None) -> dict[str, Any]:
    node_version = _command_version(["node", "--version"])
    python_version = ".".join(str(value) for value in sys.version_info[:3])
    cli = resolve_codex_security(repository)
    cli_version = _command_version([cli, "--version"]) if cli else None
    checks = {
        "node_22_or_later": bool(node_version and _version_tuple(node_version) >= (22,)),
        "python_3_10_or_later": sys.version_info >= (3, 10),
        "codex_security_installed": cli is not None,
        "codex_security_digest_pinned": cli is not None,
        "codex_security_exact_version": cli_version == UPSTREAM_PACKAGE_VERSION,
    }
    return {
        "ready": all(checks.values()),
        "checks": checks,
        "node_version": node_version,
        "python_version": python_version,
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
) -> list[str]:
    selectors = int(bool(diff)) + int(working_tree) + int(bool(paths))
    if selectors > 1:
        raise ValueError("--path, --diff, and --working-tree are mutually exclusive")
    repository_root = repository.resolve()
    output_root = output_dir.resolve()
    try:
        inside_repository = os.path.commonpath([repository_root, output_root]) == str(repository_root)
    except ValueError:
        inside_repository = False
    if inside_repository:
        raise ValueError("Output directory must be outside the scanned repository")
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
    if len(command) < 8 or Path(command[0]).name not in {"codex-security", "codex-security.cmd"}:
        raise ValueError("Refusing unexpected Codex Security executable")
    trusted = _trusted_executable(command[0])
    if trusted is None:
        raise ValueError("Refusing unpinned or digest-mismatched Codex Security executable")
    command = [str(trusted), *command[1:]]
    if command[1] != "scan" or command.count("--dry-run") != 1 or command.count("--json") != 1:
        raise ValueError("Refusing to run Codex Security without the required dry-run flags")
    if command.count("--output-dir") != 1 or command.count("--auth") != 1:
        raise ValueError("Dry run requires one output directory and one auth mode")
    auth_index = command.index("--auth")
    if auth_index + 1 >= len(command) or command[auth_index + 1] != "chatgpt":
        raise ValueError("Dry run requires chatgpt authentication")
    try:
        output_dir = Path(command[command.index("--output-dir") + 1])
    except (ValueError, IndexError) as error:
        raise ValueError("Dry run requires an explicit output directory") from error
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output_dir.stat().st_mode & 0o077:
        raise ValueError("Output directory must be owner-only (mode 0700)")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not any(marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))
    }
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=environment,
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
            rule_id = str(result.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            message_data = result.get("message", {})
            message = message_data.get("text") if isinstance(message_data, dict) else str(message_data)
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
                    "message": str(message or ""),
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
        "source_file": str(source.resolve()),
        "upstream_commit": UPSTREAM_COMMIT,
        "summary": {"total": len(findings), **{name: counts[name] for name in SEVERITIES}},
        "findings": findings,
        "learning_policy": "review findings before adding rules; never auto-train or auto-block",
    }


def load_sarif(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("SARIF input must be a regular file")
    if path.stat().st_size > MAX_SARIF_BYTES:
        raise ValueError("SARIF input exceeds 32 MiB")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to read SARIF: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("SARIF root must be an object")
    return normalize_sarif(document, path)


def write_private_output(path: Path, content: str) -> None:
    """Write output without following a caller-controlled final symlink."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Output path must be a regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
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
        command = build_dry_run_command(
            executable,
            args.repository,
            args.output_dir,
            diff=args.diff,
            working_tree=args.working_tree,
            paths=args.path,
        )
        result = run_dry_run(command)
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
