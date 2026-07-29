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
    def _runtime_fixture(self, directory: str):
        runtime = Path(directory) / "runtime"
        root = runtime / "node_modules"
        launcher = root / "@openai" / "codex-security" / "bin" / "codex-security.mjs"
        loaded_module = root / "@openai" / "codex-security" / "dist" / "cli.js"
        launcher.parent.mkdir(parents=True)
        loaded_module.parent.mkdir(parents=True)
        launcher.write_text("#!/usr/bin/env node\nimport '../dist/cli.js';\n", encoding="utf-8")
        launcher.chmod(0o755)
        loaded_module.write_text("export const trusted = true;\n", encoding="utf-8")
        (runtime / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
        manifest = runtime / "runtime-integrity-test.json"
        bridge.write_runtime_manifest(root, manifest)
        digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
        environment = {
            "CODEX_SECURITY_SHA256": digest,
            "CODEX_SECURITY_RUNTIME_MANIFEST": str(manifest),
        }
        return root, launcher, loaded_module, manifest, environment

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
        self.assertIn("--python", command)
        self.assertEqual(command.count("--path"), 2)

    def test_requires_explicit_scan_scope(self):
        with self.assertRaisesRegex(ValueError, "Exactly one explicit scan scope"):
            bridge.build_dry_run_command(
                "codex-security",
                ROOT,
                Path("/tmp/results"),
            )

    def test_rejects_path_escape_and_missing_path(self):
        for requested in ("../outside", "/tmp", "missing-path"):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    bridge.build_dry_run_command(
                        "codex-security",
                        ROOT,
                        Path("/tmp/results"),
                        paths=[requested],
                    )

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
                paths=["src"],
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
            command = bridge.build_dry_run_command(
                str(executable),
                ROOT,
                output,
                paths=["src"],
            )
            with mock.patch.dict(os.environ, {"TEST_API_TOKEN": "secret", "SAFE_VALUE": "kept", "CODEX_SECURITY_SHA256": digest}):
                with mock.patch.object(bridge.subprocess, "run") as run:
                    def result_for(args, **_kwargs):
                        output_text = "Python 3.11.0\n" if args[-1] == "--version" else ""
                        return bridge.subprocess.CompletedProcess(args, 0, output_text, "")

                    run.side_effect = result_for
                    bridge.run_dry_run(command)
            environment = run.call_args_list[-1].kwargs["env"]
            self.assertNotIn("TEST_API_TOKEN", environment)
            self.assertEqual(environment["SAFE_VALUE"], "kept")

    def test_npm_style_symlink_is_accepted_when_target_digest_is_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "codex-security.mjs"
            target.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            target.chmod(0o755)
            link = root / "codex-security"
            link.symlink_to(target)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            with mock.patch.dict(os.environ, {"CODEX_SECURITY_SHA256": digest}):
                self.assertEqual(bridge._trusted_executable(link), target.resolve())

    def test_runtime_tree_manifest_accepts_exact_dependency_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            _root, launcher, _loaded, _manifest, environment = self._runtime_fixture(directory)
            with mock.patch.dict(os.environ, environment, clear=False):
                self.assertEqual(bridge._trusted_executable(launcher), launcher.resolve())

    def test_runtime_tree_manifest_rejects_modified_loaded_module(self):
        with tempfile.TemporaryDirectory() as directory:
            _root, launcher, loaded, _manifest, environment = self._runtime_fixture(directory)
            loaded.write_text("export const trusted = false;\n", encoding="utf-8")
            with mock.patch.dict(os.environ, environment, clear=False):
                self.assertIsNone(bridge._trusted_executable(launcher))

    def test_runtime_tree_manifest_rejects_missing_or_unexpected_files(self):
        for mutation in ("missing", "unexpected"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root, launcher, loaded, _manifest, environment = self._runtime_fixture(directory)
                if mutation == "missing":
                    loaded.unlink()
                else:
                    (root / "injected.js").write_text("export default 1;\n", encoding="utf-8")
                with mock.patch.dict(os.environ, environment, clear=False):
                    self.assertIsNone(bridge._trusted_executable(launcher))

    def test_runtime_tree_manifest_rejects_changed_package_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root, launcher, _loaded, _manifest, environment = self._runtime_fixture(directory)
            (root.parent / "package-lock.json").write_text('{"lockfileVersion":2}\n', encoding="utf-8")
            with mock.patch.dict(os.environ, environment, clear=False):
                self.assertIsNone(bridge._trusted_executable(launcher))

    def test_runtime_tree_manifest_rejects_unsafe_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            _root, launcher, loaded, _manifest, environment = self._runtime_fixture(directory)
            loaded.chmod(0o777)
            with mock.patch.dict(os.environ, environment, clear=False):
                self.assertIsNone(bridge._trusted_executable(launcher))

    def test_runtime_tree_manifest_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root, launcher, _loaded, _manifest, environment = self._runtime_fixture(directory)
            outside = Path(directory) / "outside.js"
            outside.write_text("export default 1;\n", encoding="utf-8")
            (root / "escape.js").symlink_to(outside)
            with mock.patch.dict(os.environ, environment, clear=False):
                self.assertIsNone(bridge._trusted_executable(launcher))

    def test_runtime_tree_manifest_rejects_manifest_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            _root, launcher, _loaded, manifest, environment = self._runtime_fixture(directory)
            outside = Path(directory) / "copied-manifest.json"
            manifest.replace(outside)
            manifest.symlink_to(outside)
            with mock.patch.dict(os.environ, environment, clear=False):
                self.assertIsNone(bridge._trusted_executable(launcher))

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

    def test_truncates_messages_and_redacts_source_path(self):
        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"rules": []}}, "results": [{"message": {"text": "x" * 5000}}]}],
        }
        result = bridge.normalize_sarif(sarif, Path("/private/location/scan.sarif"))
        self.assertEqual(len(result["findings"][0]["message"]), bridge.MAX_MESSAGE_CHARS)
        self.assertEqual(result["source_file"], "scan.sarif")

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

    def test_private_output_and_sarif_refuse_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
            link = root / "hardlink.json"
            os.link(target, link)
            with self.assertRaises(ValueError):
                bridge.load_sarif(link)
            with self.assertRaises(ValueError):
                bridge.write_private_output(link, "replacement")


if __name__ == "__main__":
    unittest.main()
