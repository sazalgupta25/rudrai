from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import asdict
from typing import Any
from urllib.parse import quote

from .models import Finding, ScanReport, Severity


def _report_dict(report: ScanReport, include_checksum: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": "1.1.0",
        "scanner": {"name": "rudrai", "version": report.scanner_version, "rule_pack_version": report.rule_pack_version},
        "scan": {
            "target_root": report.target_root,
            "config_path": report.config_path,
            "strict": report.strict,
            "timestamp": report.timestamp,
            "status": report.status,
            "coverage": report.coverage,
            "exclusions": report.exclusions,
            "config_digest": report.config_digest,
        },
        "stats": asdict(report.stats),
        "suppression_summary": {
            "total": sum(1 for finding in report.findings if finding.suppressed),
            "by_rule": dict(Counter(f.rule_id for f in report.findings if f.suppressed)),
        },
        "findings": [finding.to_dict() for finding in report.findings],
    }
    if include_checksum:
        data["checksum"] = {"algorithm": "sha256", "value": report.checksum_sha256}
    return data


def finalize_checksum(report: ScanReport) -> None:
    canonical = json.dumps(_report_dict(report, include_checksum=False), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    report.checksum_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def render_json(report: ScanReport) -> str:
    if not report.checksum_sha256:
        finalize_checksum(report)
    return json.dumps(_report_dict(report), indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def render_sarif(report: ScanReport) -> str:
    if not report.checksum_sha256:
        finalize_checksum(report)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_name.replace(" ", ""),
                "shortDescription": {"text": finding.rule_name},
                "help": {"text": finding.remediation},
                "properties": {"category": finding.category, "defaultSeverity": finding.severity.label()},
            },
        )
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.file, safe="/")},
                    "region": {"startLine": finding.start_line, "endLine": finding.end_line},
                }
            }],
            "partialFingerprints": {"rudraiFingerprint/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity.label(),
                "confidence": finding.confidence.label(),
                "signals": finding.signals,
                "evidence": finding.evidence,
                "suppressed": finding.suppressed,
            },
        }
        if finding.suppressed:
            result["suppressions"] = [{"kind": "external", "justification": finding.suppression_reason or "Suppressed"}]
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RudrAI",
                    "version": report.scanner_version,
                    "semanticVersion": report.scanner_version,
                    "informationUri": "https://github.com/rudrai/rudrai",
                    "rules": list(rules.values()),
                }
            },
            "invocations": [{"executionSuccessful": report.status == "complete", "properties": {"strict": report.strict, "status": report.status, "coverage": report.coverage}}],
            "results": results,
            "properties": {
                "rulePackVersion": report.rule_pack_version,
                "reportChecksumSha256": report.checksum_sha256,
                "targetRoot": report.target_root,
            },
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def render_table(report: ScanReport, quiet: bool = False) -> str:
    lines: list[str] = []
    if not quiet:
        lines.extend([
            f"RudrAI Agent Security Scanner v{report.scanner_version} (rules {report.rule_pack_version})",
            f"Target: {report.target_root}",
            "",
        ])
    visible = [finding for finding in report.findings if not finding.suppressed]
    for finding in report.findings:
        status = " SUPPRESSED" if finding.suppressed else ""
        lines.append(
            f"{finding.severity.label():8} {finding.confidence.label():6} {finding.rule_id}{status} "
            f"{finding.file}:{finding.start_line}"
        )
        if not quiet:
            lines.append(f"  {finding.message}")
            lines.append(f"  Evidence: {finding.evidence}")
            lines.append(f"  Remediation: {finding.remediation}")
    if not report.findings:
        lines.append("No findings." if report.status == "complete" else "No findings in scanned files; coverage is incomplete.")
    counts = Counter(f.severity.label() for f in visible)
    lines.extend([
        "",
        f"Scanned {report.stats.scanned} files in {report.stats.duration_ms}ms; skipped {report.stats.skipped}.",
        "Findings: " + ", ".join(f"{name}={counts.get(name, 0)}" for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
        f"Suppressed: {sum(1 for finding in report.findings if finding.suppressed)}",
        f"Scan status: {report.status}",
    ])
    return "\n".join(lines) + "\n"

