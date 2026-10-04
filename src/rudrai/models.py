from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value}") from exc

    def label(self) -> str:
        return self.name


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def label(self) -> str:
        return self.name


@dataclass(slots=True)
class Finding:
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    confidence: Confidence
    file: str
    start_line: int
    end_line: int
    evidence: str
    signals: list[str]
    message: str
    remediation: str
    fingerprint: str = ""
    suppressed: bool = False
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.label()
        value["confidence"] = self.confidence.label()
        if value["suppression_reason"] is None:
            value.pop("suppression_reason")
        return value


@dataclass(slots=True)
class ScanStats:
    discovered: int = 0
    scanned: int = 0
    skipped: int = 0
    duration_ms: int = 0


@dataclass(slots=True)
class ScanReport:
    scanner_version: str
    rule_pack_version: str
    target_root: str
    config_path: str | None
    strict: bool
    timestamp: str
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    checksum_sha256: str = ""

