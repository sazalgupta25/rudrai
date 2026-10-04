from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rudrai.cli import main
from rudrai.events import EventSink
from rudrai.reporters import finalize_checksum, render_json, render_sarif
from rudrai.scanner import run_scan


class ScannerTests(unittest.TestCase):
    def test_malicious_skill_is_critical(self) -> None:
        report = run_scan(ROOT / "tests" / "fixtures" / "malicious")
        ids = {finding.rule_id for finding in report.findings}
        self.assertIn("RAI-EXEC-001", ids)
        self.assertIn("RAI-INTENT-001", ids)
        self.assertIn("RAI-PERSIST-001", ids)

    def test_benign_instructions_do_not_trigger(self) -> None:
        report = run_scan(ROOT / "tests" / "fixtures" / "benign")
        self.assertEqual([], report.findings)

    def test_mcp_and_dependency_audits(self) -> None:
        mcp = run_scan(ROOT / "tests" / "fixtures" / "mcp")
        self.assertTrue({"RAI-MCP-001", "RAI-MCP-002", "RAI-MCP-003"}.issubset({f.rule_id for f in mcp.findings}))
        dependencies = run_scan(ROOT / "tests" / "fixtures" / "dependencies")
        self.assertTrue({"RAI-DEP-001", "RAI-DEP-002"}.issubset({f.rule_id for f in dependencies.findings}))

    def test_project_urls_are_not_dependencies(self) -> None:
        report = run_scan(ROOT / "pyproject.toml")
        self.assertFalse(any(finding.rule_id == "RAI-DEP-002" for finding in report.findings))

    def test_local_reference_is_scanned(self) -> None:
        report = run_scan(ROOT / "tests" / "fixtures" / "split")
        findings = [finding for finding in report.findings if finding.file.endswith("scripts/setup.sh")]
        self.assertTrue(any(finding.rule_id == "RAI-EXEC-001" for finding in findings))
        self.assertEqual(2, report.stats.scanned)

    def test_suppression_is_visible_and_strict_ignores_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            shutil.copytree(ROOT / "tests" / "fixtures" / "malicious", target, dirs_exist_ok=True)
            (target / ".rudrai.yaml").write_text(
                "suppressions:\n"
                "  - rule_id: RAI-EXEC-001\n"
                "    path: agents/SKILL.md\n"
                "    reason: accepted test fixture\n",
                encoding="utf-8",
            )
            normal = run_scan(target)
            finding = next(item for item in normal.findings if item.rule_id == "RAI-EXEC-001")
            self.assertTrue(finding.suppressed)
            self.assertEqual("accepted test fixture", finding.suppression_reason)
            strict = run_scan(target, strict=True)
            strict_finding = next(item for item in strict.findings if item.rule_id == "RAI-EXEC-001")
            self.assertFalse(strict_finding.suppressed)

    def test_json_sarif_and_events_have_required_metadata(self) -> None:
        events = EventSink()
        report = run_scan(ROOT / "tests" / "fixtures" / "malicious", events=events)
        finalize_checksum(report)
        json_report = json.loads(render_json(report))
        sarif = json.loads(render_sarif(report))
        self.assertEqual("sha256", json_report["checksum"]["algorithm"])
        self.assertEqual("2.1.0", sarif["version"])
        self.assertIn("rulePackVersion", sarif["runs"][0]["properties"])
        self.assertEqual("scan_started", events.events[0]["type"])
        self.assertEqual("scan_completed", events.events[-1]["type"])

    def test_cli_exit_codes_and_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            code = main([
                "scan", str(ROOT / "tests" / "fixtures" / "malicious"),
                "--format", "json", "--output", str(output),
            ])
            self.assertEqual(1, code)
            self.assertGreater(len(json.loads(output.read_text(encoding="utf-8"))["findings"]), 0)
            self.assertEqual(0, main(["scan", str(ROOT / "tests" / "fixtures" / "benign"), "--quiet"]))


if __name__ == "__main__":
    unittest.main()

