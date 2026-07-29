import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def test_open_circuit_breaker_makes_doctor_unhealthy(tmp_path):
    root = tmp_path / "shield"
    cli = root / "bin" / "lyta-shield"
    cli.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "bin" / "lyta-shield", cli)
    _executable(root / "integrations" / "hermes_guard.py", "#!/bin/sh\nexit 0\n")
    _executable(root / "integrations" / "hermes-wrapper.sh", "#!/bin/sh\nexit 0\n")
    (root / "var").mkdir()
    (root / "var" / "integrity-baseline.json").write_text("{}\n", encoding="utf-8")
    (root / "var" / "circuit-breaker-open").touch()

    shim_dir = tmp_path / "bin"
    _executable(shim_dir / "python3", "#!/bin/sh\nexit 0\n")
    result = subprocess.run(
        [str(cli), "doctor"],
        env={**os.environ, "LYTA_DIR": str(root), "PATH": f"{shim_dir}:/usr/bin:/bin"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "[ALERT] circuit breaker is OPEN" in result.stdout
    assert "LYTA Shield: UNHEALTHY" in result.stdout
    assert "LYTA Shield: HEALTHY" not in result.stdout
