"""Doc-drift regressions: installer lists, release-doc paths, and README links.

These tests keep packaging and documentation claims in sync with the tree so
a moved file or a removed bypass cannot silently strand users on stale docs.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _install_file_list() -> list[str]:
    for line in (ROOT / "install.sh").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("for file in ") and stripped.endswith("; do"):
            return stripped.removeprefix("for file in ").removesuffix("; do").split()
    raise AssertionError("install.sh file list not found")


def test_installer_ships_every_guard_module():
    files = _install_file_list()
    assert "src/phish_url.py" in files
    assert "src/phish_seed_blocklist.json" in files
    for relative in files:
        assert (ROOT / relative).is_file(), f"installer references missing file: {relative}"


def test_release_doc_skill_scan_paths_exist():
    text = (ROOT / "RELEASE-v1.6.0.md").read_text(encoding="utf-8")
    assert "scripts/skill-scan" not in text
    referenced = re.findall(r"tools/skill_scan/\S+\.py", text)
    assert referenced
    for relative in referenced:
        assert (ROOT / relative).is_file(), f"release doc references missing file: {relative}"


def test_readme_local_link_targets_exist():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    targets = re.findall(r"\[[^\]]*\]\(([^)]+)\)", text)
    assert targets
    for target in targets:
        if re.match(r"(https?://|mailto:|#)", target):
            continue
        path = target.split("#", 1)[0]
        assert (ROOT / path).exists(), f"README links to missing path: {target}"


def test_removed_bypass_stays_out_of_user_docs():
    for name in ("README.md", "install.sh"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "LYTA_SHIELD_DISABLE" not in text, f"stale bypass documented in {name}"


def test_integrity_covers_phish_guard_files():
    from scripts.integrity import EXPECTED

    assert {"src/phish_url.py", "src/phish_seed_blocklist.json"}.issubset(EXPECTED)
