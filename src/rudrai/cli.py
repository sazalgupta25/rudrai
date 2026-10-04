from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import RULE_PACK_VERSION, __version__
from .config import ConfigError
from .events import EventSink
from .models import Severity
from .reporters import finalize_checksum, render_json, render_sarif, render_table
from .scanner import ScanOperationalError, run_scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rudrai", description="Offline-first AI-agent security scanner")
    parser.add_argument("--version", action="version", version=f"rudrai {__version__} (rules {RULE_PACK_VERSION})")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a local workspace or file")
    scan.add_argument("path", nargs="?", default=".", help="workspace or file to scan (default: current directory)")
    scan.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    scan.add_argument("--output", type=Path, help="write the selected output to a file")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical", "none"), default="high")
    scan.add_argument("--strict", action="store_true", help="ignore all configured suppressions")
    scan.add_argument("--include", action="append", default=[], metavar="GLOB", help="include an additional glob; repeatable")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude a glob; repeatable")
    scan.add_argument("--events-file", type=Path, help="write audit events as JSON Lines")
    scan.add_argument("--check-registries", action="store_true", help="reserved connected registry verification mode")
    scan.add_argument("--no-color", action="store_true", help="disable color output (currently the default)")
    scan.add_argument("--quiet", action="store_true", help="show only findings and the summary")
    scan.add_argument("--version", action="version", version=f"rudrai {__version__} (rules {RULE_PACK_VERSION})")
    return parser


def _write_output(value: str, destination: Path | None) -> None:
    if destination is None:
        sys.stdout.write(value)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(value, encoding="utf-8", newline="\n")


def _exit_for_findings(report, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity.parse(fail_on)
    return int(any(not finding.suppressed and finding.severity >= threshold for finding in report.findings))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "scan":
        return 2
    if args.check_registries:
        print(
            "rudrai: --check-registries is reserved for a connected-mode release and is not available in MVP-1",
            file=sys.stderr,
        )
        return 2

    events = EventSink()
    try:
        report = run_scan(
            Path(args.path),
            include=args.include,
            exclude=args.exclude,
            strict=args.strict,
            events=events,
        )
        finalize_checksum(report)
        if args.format == "json":
            rendered = render_json(report)
        elif args.format == "sarif":
            rendered = render_sarif(report)
        else:
            rendered = render_table(report, quiet=args.quiet)
        _write_output(rendered, args.output)
        if args.events_file:
            events.write(args.events_file)
        return _exit_for_findings(report, args.fail_on)
    except ConfigError as exc:
        events.emit("scan_error", kind="configuration", message=str(exc))
        if args.events_file:
            events.write(args.events_file)
        print(f"rudrai: configuration error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, ScanOperationalError) as exc:
        events.emit("scan_error", kind="operational", message=str(exc))
        if args.events_file:
            events.write(args.events_file)
        print(f"rudrai: scan failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

