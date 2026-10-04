from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


DEFAULT_NAMES = {
    "SKILL.md", "CLAUDE.md", "AGENTS.md", ".agentrules", ".cursorrules",
    "mcp.json", "mcp_config.json", "claude_desktop_config.json",
    "package.json", "requirements.txt", "pyproject.toml",
}
DEFAULT_SKIPPED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", ".next",
    "coverage", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}


@dataclass(slots=True)
class DiscoveredFile:
    path: Path
    relative: str
    kind: str
    reference_depth: int = 0


def classify(path: Path) -> str:
    name = path.name
    normalized = path.as_posix()
    if name in {"mcp.json", "mcp_config.json", "claude_desktop_config.json"}:
        return "mcp"
    if name in {"package.json", "requirements.txt", "pyproject.toml"}:
        return "dependency"
    if name in {"SKILL.md", "CLAUDE.md", "AGENTS.md", ".agentrules", ".cursorrules"}:
        return "instruction"
    if "/.cursor/rules/" in f"/{normalized}" and path.suffix == ".mdc":
        return "instruction"
    return "referenced"


def is_default_candidate(path: Path) -> bool:
    return path.name in DEFAULT_NAMES or (
        path.suffix == ".mdc" and ".cursor" in path.parts and "rules" in path.parts
    )


def _matches(relative: str, patterns: Iterable[str]) -> bool:
    relative = relative.replace("\\", "/")
    for raw in patterns:
        pattern = raw.strip().replace("\\", "/")
        if not pattern or pattern.startswith("#"):
            continue
        if pattern.startswith("!"):
            continue
        pattern = pattern.lstrip("/")
        if pattern.endswith("/") and f"/{pattern.rstrip('/')}/" in f"/{relative}/":
            return True
        if fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(relative, f"**/{pattern}"):
            return True
        if "/" not in pattern and pattern in relative.split("/"):
            return True
    return False


def _gitignore_patterns(root: Path) -> list[str]:
    path = root / ".gitignore"
    if not path.is_file():
        return []
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return []


def discover(
    target: Path,
    include: list[str],
    exclude: list[str],
    max_file_size: int,
    on_skipped: Callable[[str, str], None] | None = None,
) -> tuple[Path, list[DiscoveredFile]]:
    target = target.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    root = target if target.is_dir() else target.parent
    if target.is_symlink():
        raise ValueError("the scan target may not be a symbolic link")
    ignored = _gitignore_patterns(root)
    results: list[DiscoveredFile] = []

    def consider(path: Path, explicit: bool = False) -> None:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            if on_skipped:
                on_skipped(relative, "symlink")
            return
        if _matches(relative, exclude) or _matches(relative, ignored):
            if on_skipped:
                on_skipped(relative, "excluded")
            return
        candidate = explicit or is_default_candidate(path) or _matches(relative, include)
        if not candidate:
            return
        try:
            size = path.stat().st_size
        except OSError:
            if on_skipped:
                on_skipped(relative, "unreadable")
            return
        if size > max_file_size:
            if on_skipped:
                on_skipped(relative, f"larger than {max_file_size} bytes")
            return
        results.append(DiscoveredFile(path=path, relative=relative, kind=classify(path)))

    if target.is_file():
        consider(target, explicit=True)
    else:
        for current, dirs, files in os.walk(target, topdown=True, followlinks=False):
            current_path = Path(current)
            kept: list[str] = []
            for directory in dirs:
                candidate = current_path / directory
                relative = candidate.relative_to(root).as_posix()
                if directory in DEFAULT_SKIPPED_DIRS or candidate.is_symlink() or _matches(relative + "/", exclude + ignored):
                    if on_skipped:
                        on_skipped(relative + "/", "directory excluded")
                else:
                    kept.append(directory)
            dirs[:] = kept
            for name in files:
                consider(current_path / name)
    results.sort(key=lambda item: item.relative.casefold())
    return root, results

