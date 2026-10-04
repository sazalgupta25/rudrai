from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rudrai.scanner import run_scan


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for index in range(1000):
            folder = root / f"project-{index:04d}"
            folder.mkdir()
            (folder / "AGENTS.md").write_text(
                "# Development instructions\nUse clear names and run tests before submitting.\n",
                encoding="utf-8",
            )
        started = time.perf_counter()
        report = run_scan(root)
        elapsed = time.perf_counter() - started
        print(f"scanned={report.stats.scanned} elapsed={elapsed:.3f}s findings={len(report.findings)}")
        return 0 if report.stats.scanned == 1000 and elapsed < 1.5 else 1


if __name__ == "__main__":
    raise SystemExit(main())

