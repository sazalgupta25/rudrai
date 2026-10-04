from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence, Severity


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    name: str
    category: str
    severity: Severity
    confidence: Confidence
    remediation: str


RULES: dict[str, Rule] = {
    "RAI-EXEC-001": Rule(
        "RAI-EXEC-001", "Remote content piped to a shell", "unexpected-code-execution",
        Severity.CRITICAL, Confidence.HIGH,
        "Remove the remote execution chain and inspect the referenced content before any execution.",
    ),
    "RAI-EXEC-002": Rule(
        "RAI-EXEC-002", "Suspicious PowerShell execution", "unexpected-code-execution",
        Severity.HIGH, Confidence.HIGH,
        "Remove encoded or hidden PowerShell execution and use a reviewed local script.",
    ),
    "RAI-INTENT-001": Rule(
        "RAI-INTENT-001", "Camouflaged credential or execution intent", "human-trust-exploitation",
        Severity.CRITICAL, Confidence.HIGH,
        "Review the instruction file, remove concealed operational directives, and rotate exposed credentials.",
    ),
    "RAI-INTENT-002": Rule(
        "RAI-INTENT-002", "Stealthy or overriding agent instructions", "agent-goal-hijack",
        Severity.HIGH, Confidence.MEDIUM,
        "Remove instructions that conceal actions or override the user's security boundaries.",
    ),
    "RAI-PERSIST-001": Rule(
        "RAI-PERSIST-001", "Agent-directed persistence mechanism", "rogue-autonomy",
        Severity.HIGH, Confidence.MEDIUM,
        "Remove startup or recurring execution instructions and inspect the named persistence location.",
    ),
    "RAI-OBF-001": Rule(
        "RAI-OBF-001", "Unicode control characters", "obfuscation",
        Severity.HIGH, Confidence.HIGH,
        "Remove invisible or bidirectional control characters and review the original file source.",
    ),
    "RAI-OBF-002": Rule(
        "RAI-OBF-002", "Encoded payload-like content", "obfuscation",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Decode and review the content in an isolated environment, then replace it with transparent instructions.",
    ),
    "RAI-MCP-001": Rule(
        "RAI-MCP-001", "Unrestricted command capability", "tool-misuse",
        Severity.HIGH, Confidence.HIGH,
        "Restrict the server command and tools to an explicit allowlist.",
    ),
    "RAI-MCP-002": Rule(
        "RAI-MCP-002", "Broad or sensitive filesystem access", "excessive-permission",
        Severity.HIGH, Confidence.HIGH,
        "Replace broad filesystem roots with the smallest required project directories.",
    ),
    "RAI-MCP-003": Rule(
        "RAI-MCP-003", "Insecure remote MCP endpoint", "insecure-communication",
        Severity.HIGH, Confidence.HIGH,
        "Use an authenticated TLS endpoint and restrict it to an approved host.",
    ),
    "RAI-MCP-004": Rule(
        "RAI-MCP-004", "Suspicious MCP server launch command", "poisoned-supply-chain",
        Severity.CRITICAL, Confidence.HIGH,
        "Pin and review the local server command; do not download or pipe remote content at startup.",
    ),
    "RAI-MCP-005": Rule(
        "RAI-MCP-005", "Invalid MCP configuration", "configuration",
        Severity.MEDIUM, Confidence.HIGH,
        "Correct the JSON syntax so the complete configuration can be audited.",
    ),
    "RAI-DEP-001": Rule(
        "RAI-DEP-001", "Dangerous package lifecycle script", "poisoned-supply-chain",
        Severity.HIGH, Confidence.HIGH,
        "Remove or review lifecycle scripts that download or execute remote content.",
    ),
    "RAI-DEP-002": Rule(
        "RAI-DEP-002", "Direct URL dependency", "poisoned-supply-chain",
        Severity.MEDIUM, Confidence.HIGH,
        "Use a verified registry package with an immutable version and hash where possible.",
    ),
    "RAI-DEP-003": Rule(
        "RAI-DEP-003", "Unpinned dependency", "poisoned-supply-chain",
        Severity.LOW, Confidence.MEDIUM,
        "Pin the dependency to a reviewed version and use lock files or hashes.",
    ),
    "RAI-DEP-004": Rule(
        "RAI-DEP-004", "Package installation in agent instructions", "poisoned-supply-chain",
        Severity.MEDIUM, Confidence.MEDIUM,
        "Review and pin packages before allowing an agent to install them.",
    ),
    "RAI-REF-001": Rule(
        "RAI-REF-001", "External reference in agent instructions", "split-payload",
        Severity.LOW, Confidence.MEDIUM,
        "Review the remote origin and replace mutable URLs with pinned, verified local content when practical.",
    ),
}

