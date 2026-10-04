from __future__ import annotations

import datetime as dt
import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


@dataclass(slots=True)
class Suppression:
    rule_id: str
    path: str
    reason: str
    owner: str | None = None
    expires: dt.date | None = None

    def applies(self, rule_id: str, file_path: str, today: dt.date | None = None) -> bool:
        if self.rule_id != rule_id:
            return False
        if self.expires and self.expires < (today or dt.date.today()):
            return False
        normalized = file_path.replace("\\", "/")
        return fnmatch.fnmatchcase(normalized, self.path.replace("\\", "/"))


@dataclass(slots=True)
class Config:
    path: Path | None = None
    exclude: list[str] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)
    max_file_size: int = 1_048_576


def _scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return ""
    if value[0:1] in {'"', "'"} and value[-1:] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if value.isdigit():
        return int(value)
    return value


def _parse_schema_yaml(text: str) -> dict[str, Any]:
    """Parse the deliberately small, non-executable RudrAI configuration subset.

    JSON is accepted because it is a YAML subset. The line parser supports only the
    documented top-level scalar/list fields and suppression mappings; aliases, tags,
    folded strings, and executable constructors are rejected by construction.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ConfigError("configuration root must be a mapping")
        return parsed

    result: dict[str, Any] = {}
    section: str | None = None
    current: dict[str, Any] | None = None
    for line_number, original in enumerate(text.splitlines(), 1):
        line = original.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent]:
            raise ConfigError(f"line {line_number}: tabs are not supported")
        token = line.strip()
        if indent == 0:
            current = None
            if ":" not in token:
                raise ConfigError(f"line {line_number}: expected key: value")
            key, raw = token.split(":", 1)
            key = key.strip()
            raw = raw.strip()
            if key not in {"exclude", "suppressions", "max_file_size"}:
                raise ConfigError(f"line {line_number}: unknown key {key!r}")
            section = key
            if key in {"exclude", "suppressions"}:
                if raw not in {"", "[]"}:
                    raise ConfigError(f"line {line_number}: {key} must be a list")
                result[key] = []
            else:
                result[key] = _scalar(raw)
            continue
        if section == "exclude" and token.startswith("-"):
            result["exclude"].append(str(_scalar(token[1:].strip())))
            continue
        if section == "suppressions":
            if token.startswith("-"):
                current = {}
                result["suppressions"].append(current)
                remainder = token[1:].strip()
                if remainder:
                    if ":" not in remainder:
                        raise ConfigError(f"line {line_number}: expected suppression key: value")
                    key, raw = remainder.split(":", 1)
                    current[key.strip()] = _scalar(raw)
                continue
            if current is not None and ":" in token:
                key, raw = token.split(":", 1)
                current[key.strip()] = _scalar(raw)
                continue
        raise ConfigError(f"line {line_number}: unsupported YAML structure")
    return result


def load_config(scan_root: Path) -> Config:
    path = scan_root / ".rudrai.yaml" if scan_root.is_dir() else scan_root.parent / ".rudrai.yaml"
    if not path.is_file():
        return Config()
    try:
        raw = _parse_schema_yaml(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    exclude = raw.get("exclude", [])
    suppressions = raw.get("suppressions", [])
    max_file_size = raw.get("max_file_size", 1_048_576)
    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        raise ConfigError("exclude must be a list of glob strings")
    if not isinstance(suppressions, list):
        raise ConfigError("suppressions must be a list")
    if not isinstance(max_file_size, int) or not 1 <= max_file_size <= 100 * 1024 * 1024:
        raise ConfigError("max_file_size must be between 1 and 104857600 bytes")

    parsed_suppressions: list[Suppression] = []
    for index, item in enumerate(suppressions, 1):
        if not isinstance(item, dict):
            raise ConfigError(f"suppression {index} must be a mapping")
        unknown = set(item) - {"rule_id", "path", "reason", "owner", "expires"}
        if unknown:
            raise ConfigError(f"suppression {index} has unknown keys: {', '.join(sorted(unknown))}")
        missing = [key for key in ("rule_id", "path", "reason") if not item.get(key)]
        if missing:
            raise ConfigError(f"suppression {index} is missing: {', '.join(missing)}")
        expires = None
        if item.get("expires"):
            try:
                expires = dt.date.fromisoformat(str(item["expires"]))
            except ValueError as exc:
                raise ConfigError(f"suppression {index} has invalid ISO expiry date") from exc
        parsed_suppressions.append(
            Suppression(
                rule_id=str(item["rule_id"]),
                path=str(item["path"]),
                reason=str(item["reason"]),
                owner=str(item["owner"]) if item.get("owner") else None,
                expires=expires,
            )
        )
    return Config(path=path, exclude=exclude, suppressions=parsed_suppressions, max_file_size=max_file_size)

