from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from rudrai.cli import main
from rudrai.config import ConfigError, load_config
from rudrai.reporters import render_json, render_sarif, render_table
from rudrai.scanner import run_scan


class HardeningTests(unittest.TestCase):
    def test_nested_gitignore_negation_and_include_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (root / ".gitignore").write_text("AGENTS.md\n", encoding="utf-8")
            (root / "AGENTS.md").write_text("root", encoding="utf-8")
            (nested / ".gitignore").write_text("!AGENTS.md\n", encoding="utf-8")
            (nested / "AGENTS.md").write_text("nested", encoding="utf-8")
            self.assertEqual(1, run_scan(root).stats.scanned)
            self.assertEqual(2, run_scan(root, include=["AGENTS.md"]).stats.scanned)
            self.assertEqual(0, run_scan(root, include=["AGENTS.md"], exclude=["AGENTS.md"]).stats.scanned)

    def test_toml_dependency_groups_and_parse_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "pyproject.toml"
            manifest.write_text('[dependency-groups]\ndev = ["pkg @ https://example.com/pkg.whl"]\n', encoding="utf-8")
            self.assertIn("RAI-DEP-002", {f.rule_id for f in run_scan(root).findings})
            manifest.write_text("[broken", encoding="utf-8")
            self.assertEqual("partial", run_scan(root).status)

    def test_incomplete_files_fail_even_when_threshold_disabled(self):
        for data in (b'\x00binary', b'\xffbad encoding', b'x' * 33):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "AGENTS.md").write_bytes(data)
                (root / ".rudrai.yaml").write_text("max_file_size: 32\n", encoding="utf-8")
                report = run_scan(root)
                self.assertEqual("partial", report.status)
                self.assertEqual(0, report.stats.scanned)
                self.assertIn("coverage is incomplete", render_table(report))
                self.assertFalse(json.loads(render_sarif(report))["runs"][0]["invocations"][0]["executionSuccessful"])
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(3, main(["scan", str(root), "--fail-on", "none"]))

    def test_explicit_exclusions_do_not_fail_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "AGENTS.md").write_bytes(b'\x00')
            report = run_scan(root, exclude=["AGENTS.md"], strict=True)
            self.assertEqual("complete", report.status)
            self.assertEqual("excluded", report.coverage[0]["classification"])

    def test_missing_and_escaping_references_are_partial(self):
        for reference in ("missing.sh", "../escape.sh"):
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "SKILL.md").write_text(f"[script]({reference})", encoding="utf-8")
                self.assertEqual("partial", run_scan(root).status)

    def test_malformed_json_is_not_clean(self):
        for name in ("package.json", "mcp.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / name).write_text("{broken", encoding="utf-8")
                self.assertEqual("partial", run_scan(root).status)

    def test_checksum_detects_changed_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "AGENTS.md").write_text("Write clear prose.", encoding="utf-8")
            output = root / "report.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, main(["scan", str(root), "--format", "json", "--output", str(output)]))
                self.assertEqual(0, main(["verify", str(output)]))
                output.write_bytes(output.read_bytes() + b' ')
                self.assertEqual(1, main(["verify", str(output)]))

    def test_json_config_has_same_unknown_key_and_type_validation(self):
        for payload in ({"unknown": []}, {"max_file_size": True}, {"exclude": [1]}, {"suppressions": [{"rule_id": 1, "path": "*", "reason": "test"}]}):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".rudrai.yaml").write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ConfigError):
                    load_config(root)

    def test_target_symlink_is_rejected_before_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "AGENTS.md"
            target.write_text("text", encoding="utf-8")
            linked = root / "linked.md"
            try:
                linked.symlink_to(target)
            except OSError:
                self.skipTest("host does not grant symlink creation privileges")
            with self.assertRaises(ValueError):
                run_scan(linked)

    def test_failed_audit_output_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocker = root / "blocker"
            blocker.write_text("not a directory", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(3, main(["scan", str(root), "--events-file", str(blocker / "events.jsonl")]))

    def test_report_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "AGENTS.md"
            source.write_text("preserve this", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(3, main(["scan", str(root), "--output", str(source)]))
            self.assertEqual("preserve this", source.read_text(encoding="utf-8"))
