# RudrAI Engineering Execution Spec

**Spec Date:** 2026-09-20  
**Milestone:** MVP-1  
**Primary Deliverable:** Offline-first local CLI scanner, `rudrai scan`

## 1. Purpose

This document consolidates the resolved architecture decisions for the first buildable RudrAI milestone. It is the engineering handoff spec for implementing `rudrai scan` as an offline-first local CLI scanner for AI-agent security risks.

The decision log remains in `ENGINEERING_EXECUTION_SPEC_TRACKER.md`. This file is the implementation-facing specification.

## 2. MVP Scope

The MVP is strictly an offline-first local scanner named `rudrai scan`. It scans local repositories/workspaces for high-risk AI-agent files, agent instructions, MCP/tool configurations, and dependency manifests.

The scanner must detect poisoned agent instructions, suspicious MCP definitions, dangerous local command patterns, credential-targeting instructions, risky dependency/install patterns, and split-payload references across local files.

## 3. Non-Goals

The following are explicitly out of scope for MVP-1:

- Backend platform or hosted service.
- Dashboard/admin console.
- RBAC, multi-tenant storage, or centralized audit store.
- Runtime process interception or terminal shims.
- Chatbot/RAG gateway or production model proxy.
- Local custom rule packs.
- Rule auto-update.
- Default network calls.
- External LLM/API analysis.
- Bundled ML model.
- Standalone PyInstaller/PyOxidizer binaries.
- Cryptographic report signing/HMAC verification.

## 4. Architecture Decisions

| Area | Decision |
|---|---|
| Runtime | Python 3.10+ |
| Distribution | Standard Python package with `rudrai` console script |
| Preferred install | `pipx install rudrai` after publication |
| Backend integration boundary | JSON findings, SARIF, and JSONL event files |
| Default network behavior | No network calls |
| Supported OS targets | Windows, macOS, Linux |
| Rule source | Built-in rules shipped inside the Python package |
| Rule updates | Only through scanner package upgrades |

## 5. CLI Contract

Primary command:

```bash
rudrai scan [path]
```

Required MVP flags:

| Flag | Behavior |
|---|---|
| `--format table\|json\|sarif` | Select output format. Default is human-readable terminal output. |
| `--output <path>` | Write machine-readable output to a file. |
| `--fail-on low\|medium\|high\|critical\|none` | CI threshold. Default: `high`. |
| `--strict` | Ignore `.rudrai.yaml` suppressions. |
| `--include <glob>` | Include additional paths/patterns. Repeatable. |
| `--exclude <glob>` | Exclude paths/patterns. Repeatable. |
| `--events-file <path>` | Emit JSONL audit/events. Opt-in only. |
| `--check-registries` | Opt-in connected registry verification. May be deferred if not implemented in first build slice. |
| `--no-color` | Disable terminal colors. |
| `--quiet` | Reduce non-essential terminal output. |
| `--version` | Print scanner version and built-in rule-pack version. |

Exit-code contract:

| Code | Meaning |
|---|---|
| `0` | Scan completed; no unsuppressed finding met the fail threshold. |
| `1` | Scan completed; at least one unsuppressed finding met the fail threshold. |
| `2` | CLI usage/configuration error. |
| `3` | Scan could not complete because of operational failure. |

Default CI behavior: `--fail-on high`, so unsuppressed `HIGH` and `CRITICAL` findings return exit code `1`. `MEDIUM` and `LOW` findings do not fail CI by default.

## 6. File Discovery

MVP discovery is targeted, not whole-repo text scanning.

Default target patterns:

- `**/SKILL.md`
- `**/CLAUDE.md`
- `**/AGENTS.md`
- `**/.agentrules`
- `**/.cursorrules`
- `**/.cursor/rules/*.mdc`
- `**/mcp.json`
- `**/mcp_config.json`
- `**/claude_desktop_config.json`
- `**/package.json`
- `**/requirements.txt`
- `**/pyproject.toml`

Discovery rules:

- Respect `.gitignore` by default.
- Skip generated/vendor directories by default, including `.git`, `node_modules`, `.venv`, `venv`, `dist`, `build`, `.next`, `coverage`, and cache directories.
- Do not follow symlinks by default.
- Support `--include` and `--exclude` overrides.
- Enforce a max file size for text scanning.
- Emit skipped-file information in JSON/events when relevant.

## 7. Detection Pipeline

Detection routing is based on file type, not Tier 1 outcome.

| Tier | Name | Applies To | Behavior |
|---|---|---|---|
| Tier 1 | Deterministic heuristics | All discovered candidate files | Fast high-confidence pattern detection. |
| Tier 2 | Intent/camouflage analysis | All agent instruction files | Runs even when Tier 1 finds nothing. |
| Tier 3 | Dependency analysis | Dependency manifests and package mentions in agent instructions | Offline manifest checks by default; registry checks opt-in. |
| Tier 4 | MCP/tool config audit | MCP/tool config files | Static-only least-privilege analysis. |

All applicable tiers run, then findings are merged and deduplicated.

## 8. Tier 1 Heuristics

Tier 1 detects obvious high-risk patterns, including:

- Shell/network execution chains such as `curl | bash`, `wget`, `sh -c`.
- PowerShell execution/download patterns such as `powershell -enc`, `-nop`, `Invoke-WebRequest`, `iwr`, `Start-Process`, `bitsadmin`, `certutil -urlcache`.
- Credential/sensitive paths such as `.env`, `id_rsa`, `.ssh`, `.aws`, `.kube`, cloud credential files, and key stores.
- Windows sensitive locations such as `%USERPROFILE%\.ssh`, `%APPDATA%`, `%LOCALAPPDATA%`, PowerShell history, and Windows Credential Manager references.
- Persistence references such as `.bashrc`, `.zshrc`, cron, LaunchAgents, Task Scheduler, Registry Run keys, Startup folder, and PowerShell `$PROFILE`.
- Obfuscation indicators such as base64-like payloads, hex blobs, zero-width characters, and bidi controls.
- External egress references such as webhooks, raw IPs, paste sites, and untrusted remote scripts.

## 9. Tier 2 Intent/Camouflage Analysis

MVP Tier 2 is offline, deterministic, explainable heuristic analysis.

No external LLM/API call is allowed in MVP default behavior. No bundled ML model is included in MVP. A future optional `--deep-scan` mode may add ML/LLM analysis later.

Tier 2 uses signal clusters:

- `purpose_mismatch`: file presents as style guide/docs/persona while containing operational directives.
- `stealth_language`: silently, in background, do not inform, hidden, bypass.
- `authority_override`: ignore previous instructions, override policy, bypass verification.
- `credential_intent`: credentials, tokens, private keys, cloud profiles, env files.
- `execution_intent`: shell, PowerShell, network fetch, install, chmod, script execution.
- `persistence_intent`: startup hooks, shell profiles, scheduled tasks, registry run keys.

Findings must explain which signals contributed to the result.

## 10. MCP Audit

MVP MCP auditing is static-only.

RudrAI parses known MCP/config JSON and local command strings, but it must never:

- start an MCP server;
- connect to a live MCP server;
- introspect live MCP tools;
- execute local commands referenced by MCP config.

MVP flags:

- unrestricted shell/command tools: `bash`, `sh`, `cmd`, `powershell`, `exec`, `spawn`;
- broad filesystem roots: `/`, `C:\`, home directories, wildcard access;
- sensitive paths: `.ssh`, `.aws`, `.kube`, env files, key stores;
- insecure remote endpoints, especially plain HTTP or unknown domains;
- suspicious local server commands invoking package managers, `curl`, `wget`, PowerShell downloaders, or shell pipelines;
- missing or overly broad path/command/tool allowlists.

## 11. Dependency Analysis

Default scans make no network calls.

Offline dependency analysis should parse:

- `package.json`
- `requirements.txt`
- `pyproject.toml`
- package names/install commands found in agent instruction files

Default checks:

- dangerous lifecycle scripts;
- direct URL dependencies;
- suspicious install commands;
- package manager invocations in agent instruction files;
- unpinned risky specs where relevant;
- package names referenced by suspicious agent instructions.

npm/PyPI existence/freshness checks are opt-in only through `--check-registries`. Registry check failure must not prevent the core offline scan from completing.

## 12. Cross-File Reference Analysis

MVP follows local file references only within the scan root.

Rules:

- Follow references up to a default depth of 2 hops.
- Never execute referenced files.
- Never fetch external URLs by default.
- External URLs are recorded and scored as references, not retrieved.
- Reference graph metadata should be included in JSON/events when relevant.

This catches split-payload attacks without violating offline/static behavior.

## 13. Finding Schema

Every finding must include separate required `severity` and `confidence`.

Severity means impact if true. Confidence means certainty based on evidence.

Required finding fields:

| Field | Description |
|---|---|
| `rule_id` | Stable rule identifier. |
| `rule_name` | Human-readable rule name. |
| `category` | Threat category. |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `confidence` | `HIGH`, `MEDIUM`, or `LOW`. |
| `file` | Normalized path. |
| `start_line` | One-based start line when available. |
| `end_line` | One-based end line when available. |
| `evidence` | Short matched/explained evidence. Never whole-file dump. |
| `signals` | Explainability signals, such as `stealth_language`. |
| `message` | Human-readable summary. |
| `remediation` | Suggested action. |
| `fingerprint` | Stable deduplication fingerprint. |
| `suppressed` | Boolean. |
| `suppression_reason` | Present when suppressed. |

Report-level metadata includes scanner version, rule-pack version, target root, config path, strict mode, timestamp, and suppression summary.

## 14. Suppression Model

Suppressions are centralized in `.rudrai.yaml` only.

Inline ignore comments such as `# rudrai:ignore` are deferred.

Suppression entries require:

- `rule_id`;
- path or glob;
- reason.

Optional fields:

- owner;
- expiry date.

Suppressed findings remain visible in JSON, SARIF, and events. `--strict` ignores all suppressions.

## 15. Reports and Integrity

MVP output formats:

- human-readable terminal output;
- JSON;
- SARIF 2.1.0.

SARIF must target GitHub code scanning compatibility.

Integrity requirements:

- stable finding fingerprints based on rule ID, normalized path, location, and evidence signature;
- SHA-256 report checksums;
- scanner and rule-pack version metadata in all machine-readable outputs.

Cryptographic signing/HMAC verification is deferred.

## 16. Event Output

Structured events are opt-in via:

```bash
rudrai scan . --events-file rudrai-events.jsonl
```

Event format: JSON Lines.

Minimum event types:

- `scan_started`
- `file_discovered`
- `file_skipped`
- `finding_created`
- `finding_suppressed`
- `scan_error`
- `scan_completed`

Verbose/debug modes may add `rule_evaluated`.

Events must not include full file contents. Events are the future bridge to backend/platform ingestion.

## 17. Performance Target

The MVP performance target applies only to offline default scanning.

Target: scan 1,000 discovered candidate files in under 1.5 seconds on a typical developer machine.

Excluded from this target:

- `--check-registries`;
- future ML/LLM `--deep-scan`;
- backend/platform upload;
- any future live/introspective mode.

Implementation guidance:

- prune ignored/vendor/generated directories before file reads;
- precompile built-in rules per run;
- use bounded concurrency for file reads/rule evaluation where beneficial;
- enforce max file size limits;
- benchmark against a fixed fixture corpus.

## 18. Evaluation Corpus

The engineering spec is not execution-ready until a versioned local fixture corpus exists.

Required fixture categories:

- known-malicious Numa-style poisoned `SKILL.md`;
- stealth and persistence instructions;
- credential-targeting instructions;
- obfuscated payload examples;
- MCP overprivilege examples;
- dependency/install risk examples;
- split-payload local reference examples;
- benign DevOps docs mentioning shell commands;
- benign SSH/cloud setup docs;
- safe MCP configs;
- normal dependency manifests;
- Windows malicious and benign examples;
- 1,000-file benchmark corpus.

Tests must include expected JSON output or stable snapshot expectations. Quality gates:

- no missed critical fixtures;
- tracked false-positive budget on benign fixtures;
- stable fingerprints across runs unless evidence/location changes.

## 19. Windows Parity

Windows is first-class in MVP.

Required behavior:

- normalize paths across Windows/macOS/Linux for output and fingerprints;
- detect Windows credential/sensitive paths;
- detect PowerShell execution/download patterns;
- detect Windows persistence mechanisms;
- include Windows fixtures in the evaluation corpus.

Required Windows detection examples:

- `%USERPROFILE%\.ssh`
- `%APPDATA%`
- `%LOCALAPPDATA%`
- PowerShell history
- Windows Credential Manager references
- `powershell -enc`
- `powershell -nop`
- `Invoke-WebRequest`
- `iwr`
- `Start-Process`
- `bitsadmin`
- `certutil -urlcache`
- Task Scheduler
- Registry Run keys
- Startup folder
- PowerShell `$PROFILE`

## 20. Implementation Phases

### Phase 1: Project Skeleton and CLI

- Create Python package.
- Add `rudrai` console script.
- Implement `rudrai scan [path]`.
- Implement output mode selection.
- Implement version reporting with scanner and rule-pack version.

### Phase 2: Discovery and Config

- Implement targeted discovery.
- Respect `.gitignore`.
- Add default vendor/generated skips.
- Add symlink policy.
- Add `.rudrai.yaml` parsing for suppressions.
- Add `--include`, `--exclude`, and `--strict`.

### Phase 3: Rule Engine and Findings

- Implement built-in rule loading.
- Implement Tier 1 heuristics.
- Implement Tier 2 signal-cluster analysis.
- Implement finding schema.
- Implement severity/confidence handling.
- Implement stable fingerprints.

### Phase 4: Structured Audits

- Implement static MCP auditor.
- Implement dependency manifest parser.
- Implement local cross-file reference graph.
- Implement Windows-specific patterns.

### Phase 5: Reporting and CI

- Implement terminal reporter.
- Implement JSON reporter.
- Implement SARIF 2.1.0 reporter.
- Implement report checksums.
- Implement exit-code contract.
- Implement `--events-file` JSONL output.

### Phase 6: Evaluation and Performance

- Build fixture corpus.
- Add expected-output tests.
- Add false-positive tracking.
- Add 1,000-file benchmark.
- Validate offline scan performance target.

## 21. Acceptance Checklist

MVP-1 is execution-complete when:

- `rudrai scan [path]` runs offline by default.
- Scanner makes no network calls unless `--check-registries` is explicitly used.
- Discovery targets known agent/config/dependency files.
- Tier 2 runs on all agent instruction files regardless of Tier 1 result.
- Built-in rules ship inside the Python package.
- No local custom rules are supported.
- `.rudrai.yaml` suppressions work and remain visible in outputs.
- `--strict` ignores suppressions.
- Findings include severity and confidence.
- JSON and SARIF outputs include scanner/rule-pack versions.
- SARIF is valid SARIF 2.1.0.
- Reports include stable fingerprints and SHA-256 checksums.
- MCP audit is static-only.
- Cross-file references are followed locally to depth 2.
- External URLs are recorded but not fetched.
- Windows-specific detections are present.
- JSONL events are emitted only when `--events-file` is used.
- `--fail-on high` is the default CI threshold.
- 1,000 candidate files scan in under 1.5 seconds in the benchmark fixture.
- Evaluation corpus exists and passes required quality gates.

## 22. Deferred Decisions

The following remain intentionally deferred:

- backend/platform architecture;
- dashboard/admin console;
- local runtime shield or shell interception;
- chatbot/RAG/model gateway;
- local custom rules;
- remote signed rule update channel;
- cryptographic report signing/HMAC verification;
- default registry checks;
- bundled ML model;
- external LLM/API `--deep-scan`;
- standalone binaries;
- inline ignore comments.
