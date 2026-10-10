from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable
from pathspec import GitIgnoreSpec


DEFAULT_NAMES = {
    "SKILL.md", "CLAUDE.md", "AGENTS.md", ".agentrules", ".cursorrules",
    "mcp.json", "mcp_config.json", "claude_desktop_config.json",
    "package.json", "requirements.txt", "pyproject.toml",
}
DEFAULT_SKIPPED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", ".next",
    "coverage", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}


def is_link(path: Path) -> bool:
    """Reject symlinks and Windows reparse points, including junctions."""
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def validate_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path.expanduser()))
    for component in [*reversed(absolute.parents), absolute]:
        if is_link(component):
            raise ValueError(f"symbolic links/reparse points are not allowed: {component}")
    return absolute


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
    target = validate_path(target)
    if not target.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    root = target if target.is_dir() else target.parent
    ignores: dict[Path, GitIgnoreSpec] = {}
    exclude_spec = GitIgnoreSpec.from_lines(exclude)
    include_spec = GitIgnoreSpec.from_lines(include)
    results: list[DiscoveredFile] = []
    budget_exceeded = False

    def load_ignore(directory: Path) -> None:
        path = directory / ".gitignore"
        if not path.exists():
            return
        try:
            validate_path(path)
            with path.open("rb") as handle:
                data = handle.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError("ignore file exceeds 1 MiB")
            ignores[directory] = GitIgnoreSpec.from_lines(data.decode("utf-8-sig").splitlines())
        except (OSError, ValueError) as exc:
            if on_skipped:
                on_skipped(path.relative_to(root).as_posix(), f"cannot read ignore policy: {exc}")

    def ignored(path: Path, directory: bool = False) -> bool:
        result = False
        for base, spec in ignores.items():
            if base == path or base not in path.parents:
                continue
            matched = spec.check_file(path.relative_to(base).as_posix() + ("/" if directory else ""))
            if matched.include is not None:
                result = matched.include
        return result

    def consider(path: Path, explicit: bool = False) -> None:
        nonlocal budget_exceeded
        relative = path.relative_to(root).as_posix()
        if is_link(path):
            if on_skipped:
                on_skipped(relative, "symlink")
            return
        included = include_spec.match_file(relative)
        if exclude_spec.match_file(relative) or (ignored(path) and not included and not explicit):
            if on_skipped:
                on_skipped(relative, "excluded")
            return
        candidate = explicit or is_default_candidate(path) or included
        if not candidate:
            return
        if len(results) >= 10000:
            if not budget_exceeded and on_skipped:
                on_skipped(relative, "discovery budget exceeded (10000 files)")
            budget_exceeded = True
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
        load_ignore(root)
        consider(target, explicit=True)
    else:
        def walk_error(error: OSError) -> None:
            if on_skipped:
                on_skipped(str(error.filename), "directory unreadable")

        for current, dirs, files in os.walk(target, topdown=True, followlinks=False, onerror=walk_error):
            if budget_exceeded:
                break
            current_path = Path(current)
            load_ignore(current_path)
            kept: list[str] = []
            for directory in dirs:
                candidate = current_path / directory
                relative = candidate.relative_to(root).as_posix()
                linked = is_link(candidate)
                if directory in DEFAULT_SKIPPED_DIRS or linked or exclude_spec.match_file(relative + "/") or (ignored(candidate, True) and not include):
                    if on_skipped:
                        on_skipped(relative + "/", "symlink" if linked else "directory excluded")
                else:
                    kept.append(directory)
            dirs[:] = kept
            for name in files:
                consider(current_path / name)
    results.sort(key=lambda item: item.relative.casefold())
    return root, results

