"""CLI rules-source regressions: LYTA_SHIELD_RULES and fail-closed --check."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "src" / "lyta_shield.py"
MARKER = "zzz-drift-marker"


def _write_rules(path: Path, blocked_pattern: str) -> None:
    path.write_text(
        json.dumps(
            {
                "version": "test",
                "blocked": [{"pattern": blocked_pattern, "id": "drift_blocked"}],
                "suspicious": [{"pattern": "zzz-never-matches-1", "id": "drift_suspicious"}],
                "safe_installers": [
                    {"pattern": "https://zzz-never\\.invalid/install\\.sh", "id": "drift_installer"}
                ],
                "bounty_spam": [{"pattern": "zzz-never-matches-2", "id": "drift_spam"}],
            }
        ),
        encoding="utf-8",
    )


def _run_check(text: str, env: dict, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), "--check", text, *extra],
        text=True,
        capture_output=True,
        env=env,
    )


def test_rules_env_is_honored(tmp_path):
    rules = tmp_path / "rules.json"
    _write_rules(rules, MARKER)
    env = os.environ | {"LYTA_SHIELD_RULES": str(rules)}
    result = _run_check(f"please review {MARKER} here", env)
    assert result.returncode == 2
    assert "drift_blocked" in result.stdout


def test_marker_text_is_safe_under_default_rules():
    env = {key: value for key, value in os.environ.items() if key != "LYTA_SHIELD_RULES"}
    result = _run_check(f"please review {MARKER} here", env)
    assert result.returncode == 0


def test_explicit_rules_flag_overrides_env(tmp_path):
    blocking = tmp_path / "blocking.json"
    permissive = tmp_path / "permissive.json"
    _write_rules(blocking, MARKER)
    _write_rules(permissive, "zzz-never-matches-3")
    env = os.environ | {"LYTA_SHIELD_RULES": str(blocking)}
    result = _run_check(f"please review {MARKER} here", env, "--rules", str(permissive))
    assert result.returncode == 0


def test_missing_rules_env_fails_closed(tmp_path):
    env = os.environ | {"LYTA_SHIELD_RULES": str(tmp_path / "no-such-rules.json")}
    result = _run_check("echo hello", env)
    assert result.returncode == 2
    assert "Check failed" in result.stderr


def test_malformed_rules_env_fails_closed(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text('{"blocked": []}', encoding="utf-8")
    env = os.environ | {"LYTA_SHIELD_RULES": str(rules)}
    result = _run_check("echo hello", env)
    assert result.returncode == 2
    assert "Check failed" in result.stderr
