from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import RULE_PACK_VERSION, __version__
from .config import Config, load_config
from .detectors import detect_dependencies, detect_mcp, detect_text, extract_local_references
from .discovery import DiscoveredFile, classify, discover
from .events import EventSink
from .models import Finding, ScanReport, ScanStats
from .rules import RULES


class ScanOperationalError(RuntimeError):
    pass


def _normalize_relative(root: Path, path: Path) -> str:
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    return relative.casefold() if os.name == "nt" else relative


def _fingerprint(finding: Finding) -> str:
    evidence_signature = hashlib.sha256(finding.evidence.encode("utf-8")).hexdigest()[:16]
    value = f"{finding.rule_id}\0{finding.file}\0{finding.start_line}\0{finding.end_line}\0{evidence_signature}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ScanOperationalError(f"cannot read {path}: {exc}") from exc
    if b"\x00" in data[:8192]:
        raise ScanOperationalError(f"binary file cannot be scanned as text: {path}")
    return data.decode("utf-8-sig", errors="replace")


def _analyze(item: DiscoveredFile, text: str) -> list[Finding]:
    findings = detect_text(item.relative, text, item.kind == "instruction")
    if item.kind == "mcp":
        findings.extend(detect_mcp(item.relative, text))
    if item.kind == "dependency":
        findings.extend(detect_dependencies(item.path, item.relative, text))
    return findings


def _expand_references(
    root: Path,
    items: list[DiscoveredFile],
    texts: dict[Path, str],
    max_file_size: int,
    events: EventSink,
) -> list[DiscoveredFile]:
    root_resolved = root.resolve()
    known = {item.path for item in items}
    frontier = list(items)
    expanded: list[DiscoveredFile] = []
    for depth in (1, 2):
        next_frontier: list[DiscoveredFile] = []
        for source in frontier:
            if source.kind not in {"instruction", "referenced"}:
                continue
            text = texts.get(source.path, "")
            for raw in extract_local_references(text):
                candidate = (source.path.parent / raw).resolve()
                try:
                    candidate.relative_to(root_resolved)
                except ValueError:
                    events.emit("file_skipped", file=raw, reason="reference escapes scan root", source=source.relative)
                    continue
                if candidate in known or not candidate.is_file() or candidate.is_symlink():
                    continue
                try:
                    if candidate.stat().st_size > max_file_size:
                        events.emit("file_skipped", file=candidate.as_posix(), reason="referenced file too large")
                        continue
                    candidate_text = _read(candidate)
                except (OSError, ScanOperationalError) as exc:
                    events.emit("file_skipped", file=candidate.as_posix(), reason=str(exc))
                    continue
                item = DiscoveredFile(
                    path=candidate,
                    relative=_normalize_relative(root, candidate),
                    kind=classify(candidate),
                    reference_depth=depth,
                )
                known.add(candidate)
                texts[candidate] = candidate_text
                expanded.append(item)
                next_frontier.append(item)
                events.emit("file_discovered", file=item.relative, kind=item.kind, reference_depth=depth)
        frontier = next_frontier
        if not frontier:
            break
    return expanded


def run_scan(
    target: Path,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    strict: bool = False,
    events: EventSink | None = None,
) -> ScanReport:
    started = time.perf_counter()
    event_sink = events or EventSink()
    resolved = target.expanduser().resolve()
    config: Config = load_config(resolved if resolved.is_dir() else resolved.parent)
    all_excludes = [*config.exclude, *(exclude or [])]
    skipped_count = 0
    event_sink.emit(
        "scan_started",
        target=(resolved if resolved.is_dir() else resolved.parent).as_posix(),
        scanner_version=__version__,
        rule_pack_version=RULE_PACK_VERSION,
        strict=strict,
    )

    def on_skipped(file: str, reason: str) -> None:
        nonlocal skipped_count
        skipped_count += 1
        event_sink.emit("file_skipped", file=file, reason=reason)

    root, items = discover(
        resolved,
        include=include or [],
        exclude=all_excludes,
        max_file_size=config.max_file_size,
        on_skipped=on_skipped,
    )
    for item in items:
        event_sink.emit("file_discovered", file=item.relative, kind=item.kind, reference_depth=0)

    texts: dict[Path, str] = {}
    readable_items: list[DiscoveredFile] = []
    read_workers = min(16, max(1, len(items)))
    with ThreadPoolExecutor(max_workers=read_workers, thread_name_prefix="rudrai-read") as read_pool:
        read_futures = [read_pool.submit(_read, item.path) for item in items]
        for item, future in zip(items, read_futures):
            try:
                texts[item.path] = future.result()
                readable_items.append(item)
            except ScanOperationalError as exc:
                skipped_count += 1
                event_sink.emit("file_skipped", file=item.relative, reason=str(exc))
    items = readable_items
    items.extend(_expand_references(root, items, texts, config.max_file_size, event_sink))

    workers = min(32, max(1, (os.cpu_count() or 1) + 4), max(1, len(items)))
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rudrai") as pool:
        futures = [pool.submit(_analyze, item, texts[item.path]) for item in items]
        for future in futures:
            findings.extend(future.result())

    unique: dict[str, Finding] = {}
    for finding in findings:
        finding.file = finding.file.replace("\\", "/")
        finding.fingerprint = _fingerprint(finding)
        if not strict:
            for suppression in config.suppressions:
                if suppression.applies(finding.rule_id, finding.file):
                    finding.suppressed = True
                    finding.suppression_reason = suppression.reason
                    event_sink.emit(
                        "finding_suppressed",
                        rule_id=finding.rule_id,
                        file=finding.file,
                        fingerprint=finding.fingerprint,
                        reason=suppression.reason,
                    )
                    break
        dedupe_key = f"{finding.rule_id}:{finding.file}:{finding.start_line}:{finding.evidence}"
        existing = unique.get(dedupe_key)
        if existing is None or (finding.confidence, finding.severity) > (existing.confidence, existing.severity):
            unique[dedupe_key] = finding

    findings = sorted(
        unique.values(),
        key=lambda item: (-int(item.severity), -int(item.confidence), item.file.casefold(), item.start_line, item.rule_id),
    )
    for finding in findings:
        if not finding.suppressed:
            event_sink.emit(
                "finding_created",
                rule_id=finding.rule_id,
                severity=finding.severity.label(),
                confidence=finding.confidence.label(),
                file=finding.file,
                start_line=finding.start_line,
                fingerprint=finding.fingerprint,
            )

    duration_ms = round((time.perf_counter() - started) * 1000)
    report = ScanReport(
        scanner_version=__version__,
        rule_pack_version=RULE_PACK_VERSION,
        target_root=root.as_posix(),
        config_path=config.path.as_posix() if config.path else None,
        strict=strict,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        findings=findings,
        stats=ScanStats(discovered=len(items), scanned=len(items), skipped=skipped_count, duration_ms=duration_ms),
    )
    event_sink.emit(
        "scan_completed",
        scanned=report.stats.scanned,
        skipped=report.stats.skipped,
        findings=len(findings),
        duration_ms=duration_ms,
    )
    return report


def rule_count() -> int:
    return len(RULES)

