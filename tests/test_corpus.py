from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rudrai.scanner import run_scan


CORPUS = ROOT / "tests" / "corpus" / "v1"


def _actual_finding(finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.label(),
        "confidence": finding.confidence.label(),
        "file": finding.file,
        "start_line": finding.start_line,
    }


class EvaluationCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((CORPUS / "expectations.json").read_text(encoding="utf-8"))

    def test_v1_labeled_cases_match_expected_findings(self) -> None:
        false_positives = 0
        critical_cases = 0
        for case in self.manifest["cases"]:
            with self.subTest(case=case["id"]):
                report = run_scan(CORPUS / case["path"])
                self.assertEqual("complete", report.status)
                actual = sorted((_actual_finding(item) for item in report.findings), key=str)
                expected = sorted(case["expected_findings"], key=str)
                self.assertEqual(expected, actual)
                repeated = run_scan(CORPUS / case["path"])
                self.assertEqual(
                    [item.fingerprint for item in report.findings],
                    [item.fingerprint for item in repeated.findings],
                    "finding fingerprints must remain stable across identical scans",
                )
                if case["classification"] == "benign":
                    false_positives += len(actual)
                if case.get("critical"):
                    critical_cases += 1
                    self.assertTrue(any(item["severity"] == "CRITICAL" for item in actual))
        self.assertGreater(critical_cases, 0)
        self.assertLessEqual(false_positives, self.manifest["false_positive_budget"])

    def test_contextual_cluster_is_explainable(self) -> None:
        report = run_scan(CORPUS / "cases" / "malicious-camouflaged-credentials")
        intent = next(item for item in report.findings if item.rule_id == "RAI-INTENT-001")
        self.assertIn("nearby_signal_cluster", intent.signals)


if __name__ == "__main__":
    unittest.main()
