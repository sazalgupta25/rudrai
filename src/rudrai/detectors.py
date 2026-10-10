from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from .models import Confidence, Finding, Severity
from .rules import RULES


REMOTE_SHELL = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest)\b[^|;]{0,400}(?:\||;)\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
POWERSHELL_RISK = re.compile(
    r"(?:powershell(?:\.exe)?\s+[^\n]{0,200}(?:-(?:enc(?:odedcommand)?|nop|w\s+hidden))|"
    r"(?:invoke-webrequest|\biwr\b|start-process|bitsadmin|certutil\s+-urlcache))",
    re.IGNORECASE,
)
CREDENTIAL = re.compile(
    r"(?:~[/\\]\.?(?:ssh|aws|kube)|\.env\b|id_rsa|aws[/\\]credentials|"
    r"(?:%userprofile%|\$env:userprofile)[/\\]\.ssh|%appdata%|%localappdata%|credential manager|keychain)",
    re.IGNORECASE,
)
EXECUTION = re.compile(
    r"(?:\b(?:curl|wget|bash|sh|cmd|powershell|exec|spawn|chmod)\b|"
    r"invoke-webrequest|start-process|npm\s+(?:install|i)\b|pip(?:3)?\s+install\b)",
    re.IGNORECASE,
)
STEALTH = re.compile(
    r"(?:silently|in the background|do not (?:inform|tell|notify)|without (?:informing|telling|notifying)|hidden)",
    re.IGNORECASE,
)
OVERRIDE = re.compile(
    r"(?:ignore (?:all )?(?:previous|prior) instructions|override (?:the )?(?:policy|rules)|"
    r"bypass (?:verification|approval|security)|disregard (?:the )?(?:policy|instructions))",
    re.IGNORECASE,
)
PERSISTENCE = re.compile(
    r"(?:\.bashrc|\.zshrc|\bcron(?:tab)?\b|launchagents|task scheduler|schtasks|"
    r"registry .{0,30}\brun\b|hk(?:cu|lm)[^\n]{0,120}[/\\]run\b|startup folder|\$profile\b|on every (?:prompt|session|startup))",
    re.IGNORECASE,
)
BENIGN_PURPOSE = re.compile(
    r"(?:style guide|writing guide|formatting|documentation|persona|tone guide|linting)",
    re.IGNORECASE,
)
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
UNICODE_CONTROLS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
INSTALL_COMMAND = re.compile(r"\b(?:pip(?:3)?\s+install|npm\s+(?:install|i)|npx)\s+([^\n`]+)", re.IGNORECASE)
DIRECT_URL = re.compile(r"(?:https?://|git\+https?://|github:|git@)", re.IGNORECASE)
EXTERNAL_URL = re.compile(r"https?://[^\s)>'\"`]+", re.IGNORECASE)
NEGATED_OR_QUOTED = re.compile(
    r"(?:\b(?:do not|don't|never|avoid|prohibited|forbidden|must not|should not)\b|^\s*>)",
    re.IGNORECASE,
)
REFERENCE_PATTERNS = [
    re.compile(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)", re.IGNORECASE),
    re.compile(r"^\s*(?:source|script|file)\s*:\s*[\"']?([^\"'\s#]+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"(?:^|\s)((?:\.?\.?[/\\])[^\s'\"`]+\.(?:sh|ps1|py|js|cmd|bat))\b", re.IGNORECASE),
]


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _evidence(text: str, match: re.Match[str] | None = None) -> str:
    value = match.group(0) if match else text
    value = " ".join(value.strip().split())
    return value[:237] + "..." if len(value) > 240 else value


def _finding(
    rule_id: str,
    relative: str,
    text: str,
    match: re.Match[str] | None,
    signals: Iterable[str],
    message: str,
    *,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    evidence: str | None = None,
) -> Finding:
    rule = RULES[rule_id]
    start_line = _line(text, match.start()) if match else 1
    end_line = _line(text, match.end()) if match else start_line
    return Finding(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        category=rule.category,
        severity=severity if severity is not None else rule.severity,
        confidence=confidence or rule.confidence,
        file=relative,
        start_line=start_line,
        end_line=end_line,
        evidence=evidence if evidence is not None else _evidence(text, match),
        signals=sorted(set(signals)),
        message=message,
        remediation=rule.remediation,
    )


def _line_bounds(text: str, offset: int) -> tuple[int, int]:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return start, len(text) if end == -1 else end


def _is_non_executing_context(text: str, match: re.Match[str]) -> bool:
    """Return true for a quoted or explicitly prohibited command on its line.

    This is deliberately narrow: it only suppresses a match where the surrounding
    instruction explicitly says not to perform it, rather than trying to infer the
    safety of arbitrary prose.
    """
    start, end = _line_bounds(text, match.start())
    line = text[start:end]
    return bool(NEGATED_OR_QUOTED.search(line))


def _active_matches(pattern: re.Pattern[str], text: str) -> list[re.Match[str]]:
    return [match for match in pattern.finditer(text) if not _is_non_executing_context(text, match)]


def _nearby(*matches: re.Match[str] | None, max_lines: int = 12) -> bool:
    """Require related intent signals to appear in the same local instruction block."""
    selected = [match for match in matches if match is not None]
    if len(selected) < 2:
        return bool(selected)
    lines = [match.string.count("\n", 0, match.start()) for match in selected]
    return max(lines) - min(lines) <= max_lines


def detect_text(relative: str, text: str, instruction: bool) -> list[Finding]:
    findings: list[Finding] = []
    remote = next(iter(_active_matches(REMOTE_SHELL, text)), None)
    powershell = next(iter(_active_matches(POWERSHELL_RISK, text)), None)
    credential = next(iter(_active_matches(CREDENTIAL, text)), None)
    execution = next(iter(_active_matches(EXECUTION, text)), None)
    stealth = next(iter(_active_matches(STEALTH, text)), None)
    override = next(iter(_active_matches(OVERRIDE, text)), None)
    persistence = next(iter(_active_matches(PERSISTENCE, text)), None)
    purpose = BENIGN_PURPOSE.search(text[:2000])
    unicode_control = UNICODE_CONTROLS.search(text)
    encoded = BASE64_BLOB.search(text)

    if remote:
        findings.append(_finding(
            "RAI-EXEC-001", relative, text, remote,
            ["execution_intent", "external_egress"], "Remote content is piped directly into a shell.",
        ))
    if powershell:
        findings.append(_finding(
            "RAI-EXEC-002", relative, text, powershell,
            ["execution_intent", "powershell"], "The file contains a high-risk PowerShell execution or download primitive.",
        ))
    if unicode_control:
        findings.append(_finding(
            "RAI-OBF-001", relative, text, unicode_control,
            ["unicode_obfuscation"], "Invisible or bidirectional Unicode controls can conceal the displayed instruction.",
            evidence=f"Unicode control U+{ord(unicode_control.group(0)):04X}",
        ))
    if encoded:
        findings.append(_finding(
            "RAI-OBF-002", relative, text, encoded,
            ["encoded_payload"], "A long encoded token may conceal an executable payload.",
        ))

    if instruction:
        clustered = [
            ("credential_intent", credential), ("execution_intent", execution),
            ("stealth_language", stealth), ("authority_override", override),
            ("persistence_intent", persistence), ("purpose_mismatch", purpose),
        ]
        signals = [name for name, match in clustered if match]
        if purpose and execution and (credential or stealth or persistence) and _nearby(execution, credential or stealth or persistence):
            anchor = execution
            findings.append(_finding(
                "RAI-INTENT-001", relative, text, anchor, [*signals, "nearby_signal_cluster"],
                "A document presented as benign guidance contains concealed operational behavior.",
            ))
        elif credential and execution and (stealth or override) and _nearby(credential, execution, stealth or override):
            anchor = stealth or override or execution
            findings.append(_finding(
                "RAI-INTENT-001", relative, text, anchor, [*signals, "nearby_signal_cluster"],
                "Credential targeting is combined with execution and concealment instructions.",
            ))
        if (override and (execution or credential) and _nearby(override, execution or credential)) or (stealth and execution and _nearby(stealth, execution)):
            anchor = override or stealth
            confidence = Confidence.HIGH if override and execution and _nearby(override, execution) else Confidence.MEDIUM
            findings.append(_finding(
                "RAI-INTENT-002", relative, text, anchor, [*signals, "nearby_signal_cluster"],
                "The agent is instructed to hide an action or bypass established authority.",
                confidence=confidence,
            ))
        if persistence and (execution or stealth) and _nearby(persistence, execution or stealth):
            findings.append(_finding(
                "RAI-PERSIST-001", relative, text, persistence, [*signals, "nearby_signal_cluster"],
                "The agent is instructed to establish recurring or startup execution.",
                confidence=Confidence.HIGH if stealth else Confidence.MEDIUM,
            ))
        install = next(iter(_active_matches(INSTALL_COMMAND, text)), None)
        if install:
            findings.append(_finding(
                "RAI-DEP-004", relative, text, install,
                ["dependency_install", "execution_intent"],
                "Agent instructions direct package installation without independent verification.",
            ))
        external = next(iter(_active_matches(EXTERNAL_URL, text)), None)
        if external:
            findings.append(_finding(
                "RAI-REF-001", relative, text, external,
                ["external_reference"],
                "Agent instructions reference external content; it was recorded but not fetched.",
            ))
    return findings


def _walk_json(value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_json(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json(child, f"{path}[{index}]")


def detect_mcp(relative: str, text: str) -> list[Finding]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return [_finding(
            "RAI-MCP-005", relative, text, None, ["invalid_json"],
            "The MCP configuration is not valid JSON and could not be fully audited.",
            evidence=f"{exc.msg} at line {exc.lineno}, column {exc.colno}",
        )]
    findings: list[Finding] = []
    for json_path, value in _walk_json(payload):
        if not isinstance(value, str):
            continue
        lowered_path = json_path.casefold()
        lowered = value.casefold().strip()
        if any(token in lowered for token in ("curl", "wget", "invoke-webrequest")) and (
            "|" in value or ";" in value
        ):
            findings.append(_finding(
                "RAI-MCP-004", relative, text, None, ["server_command", "external_egress"],
                "An MCP server command downloads and executes remote content.", evidence=f"{json_path}: {_evidence(value)}",
            ))
        if any(token in lowered for token in ("bash", "powershell", "cmd.exe", "sh -c")) and any(
            token in lowered_path for token in ("command", "tool", "args")
        ):
            findings.append(_finding(
                "RAI-MCP-001", relative, text, None, ["unrestricted_shell"],
                "The MCP configuration exposes or launches an unrestricted command interpreter.",
                evidence=f"{json_path}: {_evidence(value)}",
            ))
        normalized = value.replace("\\", "/")
        if lowered in {"/", "c:\\", "c:/", "*", "**", "~"} or CREDENTIAL.search(normalized):
            findings.append(_finding(
                "RAI-MCP-002", relative, text, None, ["broad_filesystem", "sensitive_path"],
                "The MCP configuration grants broad or sensitive filesystem access.", evidence=f"{json_path}: {value}",
            ))
        if re.search(r"(?<![a-z])(?:http|ws)://", lowered):
            findings.append(_finding(
                "RAI-MCP-003", relative, text, None, ["insecure_transport"],
                "The MCP endpoint uses an unencrypted transport.", evidence=f"{json_path}: {value}",
            ))
    return findings


def detect_dependencies(path: Path, relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if path.name == "package.json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return findings
        scripts = payload.get("scripts", {}) if isinstance(payload, dict) else {}
        if isinstance(scripts, dict):
            for name in ("preinstall", "install", "postinstall", "prepare"):
                command = scripts.get(name)
                if isinstance(command, str) and (REMOTE_SHELL.search(command) or POWERSHELL_RISK.search(command)):
                    findings.append(_finding(
                        "RAI-DEP-001", relative, text, None, ["lifecycle_script", "execution_intent"],
                        f"The npm {name} lifecycle script performs dangerous download or execution behavior.",
                        evidence=f"scripts.{name}: {_evidence(command)}",
                    ))
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = payload.get(section, {}) if isinstance(payload, dict) else {}
            if isinstance(deps, dict):
                for name, version in deps.items():
                    if isinstance(version, str) and DIRECT_URL.search(version):
                        findings.append(_finding(
                            "RAI-DEP-002", relative, text, None, ["direct_url_dependency"],
                            f"Dependency {name} is installed from a direct URL or Git source.", evidence=f"{name}: {version}",
                        ))
    elif path.name == "requirements.txt":
        for line_number, raw in enumerate(text.splitlines(), 1):
            value = raw.strip()
            if not value or value.startswith(("#", "-r", "--requirement")):
                continue
            if DIRECT_URL.search(value):
                findings.append(_finding(
                    "RAI-DEP-002", relative, text, None, ["direct_url_dependency"],
                    "A Python dependency is installed from a direct URL or Git source.", evidence=value,
                ))
                findings[-1].start_line = findings[-1].end_line = line_number
            elif not re.search(r"(?:===|==|~=)\s*[^\s;]+", value):
                findings.append(_finding(
                    "RAI-DEP-003", relative, text, None, ["unpinned_dependency"],
                    "A Python dependency does not use an exact or compatible-release pin.", evidence=value,
                ))
                findings[-1].start_line = findings[-1].end_line = line_number
    elif path.name == "pyproject.toml":
        payload = tomllib.loads(text)  # Reject malformed manifests; never silently mark them clean.
        dependencies: list[Any] = []
        project = payload.get("project", {})
        if not isinstance(project, dict):
            raise ValueError("project must be a TOML table")
        dependencies.extend(project.get("dependencies", []))
        for values in project.get("optional-dependencies", {}).values():
            dependencies.extend(values)
        for values in payload.get("dependency-groups", {}).values():
            dependencies.extend(values)
        poetry = payload.get("tool", {}).get("poetry", {})
        tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
        tables.extend(group.get("dependencies", {}) for group in poetry.get("group", {}).values())
        for table in tables:
            for name, value in table.items():
                if isinstance(value, dict) and any(key in value for key in ("url", "git", "path")):
                    dependencies.append(f"{name} @ {value.get('url', value.get('git', value.get('path')))}")
                elif isinstance(value, str):
                    dependencies.append(value)
        for value in dependencies:
            if isinstance(value, dict) and set(value) == {"include-group"}:
                continue
            if not isinstance(value, str):
                raise ValueError("dependency entries must be strings or include-group mappings")
            if DIRECT_URL.search(value):
                findings.append(_finding("RAI-DEP-002", relative, text, None, ["direct_url_dependency"],
                    "A Python dependency is installed from a direct URL or Git source.", evidence=_evidence(value)))
        return findings
    return findings


def extract_local_references(text: str) -> list[str]:
    values: list[str] = []
    for pattern in REFERENCE_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1).strip().split("#", 1)[0]
            if value and value not in values:
                values.append(value)
    return values

