import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "lyta-shield"


def test_self_heal_without_file_is_safe_under_bash_nounset(tmp_path):
    fake_root = tmp_path / "shield"
    (fake_root / "integrations").mkdir(parents=True)
    (fake_root / "integrations" / "hermes_guard.py").write_text("# test guard\n", encoding="utf-8")
    (fake_root / "scripts").mkdir()
    (fake_root / "scripts" / "integrity.py").write_text("# test integrity\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "python-args.txt"
    python = fake_bin / "python3"
    python.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$LYTA_TEST_CAPTURE\"\n",
        encoding="utf-8",
    )
    python.chmod(0o700)

    env = {
        **os.environ,
        "LYTA_DIR": str(fake_root),
        "LYTA_TEST_CAPTURE": str(capture),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
    }
    result = subprocess.run(
        ["bash", str(CLI), "self-heal"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert capture.read_text(encoding="utf-8").splitlines() == [
        str(fake_root / "scripts" / "integrity.py"),
        "heal",
    ]
