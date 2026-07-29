import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def test_release_workflow_is_tag_gated_reproducible_and_attested():
    workflow = RELEASE.read_text(encoding="utf-8")
    assert 'tags:' in workflow and '"v*"' in workflow
    assert "git describe --tags --exact-match" in workflow
    assert "--require-hashes -r requirements-build.lock" in workflow
    assert workflow.count("git archive HEAD") >= 2
    assert "cmp /tmp/lyta-build-a/dist/*.whl" in workflow
    assert "cmp /tmp/lyta-build-a/dist/*.tar.gz" in workflow
    assert "actions/attest-build-provenance@" in workflow
    assert "gh release create" in workflow
    assert "persist-credentials: false" in workflow


def test_all_workflow_actions_are_commit_pinned():
    for path in (CI, RELEASE):
        workflow = path.read_text(encoding="utf-8")
        uses = re.findall(r"uses:\s+([^\s#]+)", workflow)
        assert uses
        for action in uses:
            reference = action.rsplit("@", 1)[-1]
            assert re.fullmatch(r"[0-9a-f]{40}", reference), f"floating action in {path.name}: {action}"


def test_release_toolchain_is_exact_and_hash_locked():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lock = (ROOT / "requirements-build.lock").read_text(encoding="utf-8")
    assert 'requires = ["hatchling==1.27.0"]' in pyproject
    for package in ("build", "exceptiongroup", "hatchling", "pytest", "pynacl", "ruff", "tomli", "typing-extensions"):
        assert re.search(rf"^{package}==[^\s]+", lock, re.MULTILINE)
    assert "--hash=sha256:" in lock
    assert ">=" not in lock


def test_sbom_generator_is_deterministic(tmp_path):
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    assert version_match is not None
    version = version_match.group(1)
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}
    outputs = [tmp_path / "a.json", tmp_path / "b.json"]
    for output in outputs:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate-release-sbom.py"),
                "--output",
                str(output),
                "--commit",
                "a" * 40,
                "--tag",
                f"v{version}",
            ],
            cwd=ROOT,
            env=env,
            check=True,
        )
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    document = json.loads(outputs[0].read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"


def test_release_requires_signed_tag_exact_main_sha_and_green_push_ci_before_build():
    workflow = RELEASE.read_text(encoding="utf-8")
    gate = workflow.index("- name: Require signed annotated tag, exact main commit, and green push CI")
    build = workflow.index("- name: Install hash-locked release toolchain")
    assert gate < build
    for required in (
        "actions: read",
        'git/ref/tags/${GITHUB_REF_NAME}',
        'test "${tag_type}" = "tag"',
        'git/tags/${tag_object_sha}',
        ".verification.verified",
        'test "${tag_record}" = "${expected_tag_record}"',
        'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha',
        "--workflow ci.yml",
        "--branch main",
        '--commit "${GITHUB_SHA}"',
        "--event push",
        "--status success",
        'test "${ci_record}" = "${expected_record}"',
    ):
        assert required in workflow
