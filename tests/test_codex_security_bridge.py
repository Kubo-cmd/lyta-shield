import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "codex_security_bridge", ROOT / "integrations" / "codex_security_bridge.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load Codex Security bridge")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class CodexSecurityBridgeTests(unittest.TestCase):
    def test_build_dry_run_is_offline_guarded(self):
        command = bridge.build_dry_run_command(
            "/usr/local/bin/codex-security",
            ROOT,
            Path("/tmp/lyta-codex-security-results"),
            paths=["src", "integrations"],
        )
        self.assertIn("--dry-run", command)
        self.assertIn("--json", command)
        self.assertIn("--auth", command)
        self.assertIn("chatgpt", command)
        self.assertEqual(command.count("--path"), 2)

    def test_diff_and_working_tree_conflict(self):
        with self.assertRaises(ValueError):
            bridge.build_dry_run_command(
                "codex-security",
                ROOT,
                Path("/tmp/results"),
                diff="origin/main",
                working_tree=True,
            )

    def test_paths_and_working_tree_conflict(self):
        with self.assertRaises(ValueError):
            bridge.build_dry_run_command(
                "codex-security",
                ROOT,
                Path("/tmp/results"),
                working_tree=True,
                paths=["src"],
            )

    def test_output_inside_repository_is_rejected(self):
        with self.assertRaises(ValueError):
            bridge.build_dry_run_command(
                "codex-security",
                ROOT,
                ROOT / ".codex-security-results",
            )

    def test_refuses_non_dry_run_execution(self):
        with self.assertRaises(ValueError):
            bridge.run_dry_run(["codex-security", "scan", "."])

    def test_refuses_unexpected_executable_even_with_dry_run_flag(self):
        with self.assertRaises(ValueError):
            bridge.run_dry_run(
                [
                    "/bin/echo",
                    "scan",
                    "/tmp/repo",
                    "--output-dir",
                    "/tmp/results",
                    "--dry-run",
                    "--json",
                    "--auth",
                    "chatgpt",
                ]
            )

    def test_dry_run_strips_secret_environment_values(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            output.mkdir(mode=0o700)
            executable = Path(directory) / "codex-security"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            command = [
                str(executable),
                "scan",
                "/tmp/repo",
                "--output-dir",
                str(output),
                "--dry-run",
                "--json",
                "--auth",
                "chatgpt",
            ]
            with mock.patch.dict(os.environ, {"TEST_API_TOKEN": "secret", "SAFE_VALUE": "kept", "CODEX_SECURITY_SHA256": digest}):
                with mock.patch.object(bridge.subprocess, "run") as run:
                    run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
                    bridge.run_dry_run(command)
            environment = run.call_args.kwargs["env"]
            self.assertNotIn("TEST_API_TOKEN", environment)
            self.assertEqual(environment["SAFE_VALUE"], "kept")

    def test_normalizes_sarif_and_preserves_fingerprint(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "LYTA001",
                                    "shortDescription": {"text": "Unsafe execution"},
                                    "properties": {"security-severity": "9.3"},
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "LYTA001",
                            "level": "error",
                            "message": {"text": "Untrusted input reaches execution."},
                            "partialFingerprints": {"primaryLocationLineHash": "stable-id"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/example.py"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        result = bridge.normalize_sarif(sarif, Path("scan.sarif"))
        self.assertEqual(result["summary"]["total"], 1)
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["findings"][0]["fingerprint"], "stable-id")
        self.assertEqual(result["findings"][0]["path"], "src/example.py")
        self.assertEqual(result["findings"][0]["line"], 42)

    def test_generates_stable_fingerprint(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {
                            "ruleId": "RULE",
                            "level": "warning",
                            "message": {"text": "Review this path."},
                        }
                    ],
                }
            ],
        }
        first = bridge.normalize_sarif(sarif, Path("a.sarif"))
        second = bridge.normalize_sarif(sarif, Path("b.sarif"))
        self.assertEqual(first["findings"][0]["fingerprint"], second["findings"][0]["fingerprint"])
        self.assertEqual(first["findings"][0]["severity"], "medium")

    def test_rejects_invalid_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps({"version": "1.0"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                bridge.load_sarif(path)

    def test_rejects_symlinked_and_oversized_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                bridge.load_sarif(link)
            oversized = root / "oversized.sarif"
            with oversized.open("wb") as handle:
                handle.truncate(bridge.MAX_SARIF_BYTES + 1)
            with self.assertRaises(ValueError):
                bridge.load_sarif(oversized)

    def test_private_output_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("unchanged", encoding="utf-8")
            link = root / "output.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                bridge.write_private_output(link, "replacement")
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
