# RudrAI Engineering Execution Spec Readiness Tracker

This tracker is the working control document for turning the current RudrAI product/MVP/architecture materials into an engineering execution spec.

Rule for this grilling session: only one architectural decision is active at a time. A locked item must not be started until the active item has a recorded resolution, acceptance criteria, and owner/next artifact.

## Status Legend

- `ACTIVE`: Current decision under discussion.
- `LOCKED`: Waiting for the previous item to be resolved.
- `RESOLVED`: Decision made and recorded.
- `BLOCKED`: Cannot progress without external input, research, or stakeholder decision.

## Progress Board

| # | Status | Decision / Work Item | Why It Blocks Engineering | Resolution | Acceptance Criteria / Exit Bar |
|---|---|---|---|---|---|
| 1 | RESOLVED | Define execution-spec success criteria and MVP boundary | Without a crisp endpoint, the spec can keep expanding from CLI scanner into full platform/gateway scope. | First engineering execution spec is strictly the offline-first local CLI scanner: `rudrai scan`. Backend, platform, gateway, dashboard, RBAC, audit store, and runtime interception are later-stage concerns. | One-paragraph MVP boundary, explicit non-goals, and definition of "ready for engineering execution." |
| 2 | RESOLVED | Resolve architecture stack decision | Current docs conflict between Python CLI and Java/Spring/Oracle platform. | MVP scanner uses Python 3.10+. Future backend/platform integration boundary is file-based output: JSON findings, SARIF, and structured event files. Backend/platform components remain deferred. | ADR states whether MVP is Python-only, Java-backed, or polyglot, plus integration contract. |
| 3 | RESOLVED | Redesign detection pipeline routing | Current flow risks letting Tier 1-clean files bypass semantic analysis. | Pipeline routes by file type, not Tier 1 outcome. Tier 2 intent/camouflage analysis runs on all agent instruction files by default, even when Tier 1 finds nothing. | Updated pipeline routes by file type, defines tiers, merge/dedup behavior, and latency budget. |
| 4 | RESOLVED | Specify Tier 2 semantic/intent analysis | This is the differentiator but currently underspecified. | MVP Tier 2 is an offline deterministic heuristic analyzer. It uses explainable signal clusters: purpose mismatch, stealth language, authority override, credential intent, execution intent, and persistence intent. No external LLM/API calls and no bundled ML model in MVP; optional ML/LLM `--deep-scan` is deferred. | Concrete MVP approach, data inputs, scoring method, performance target, false-positive strategy. |
| 5 | RESOLVED | Threat-model RudrAI itself | Scanner rules, configs, updates, registry calls, and reports are attack surfaces. | MVP ships built-in versioned rules only. Local custom rules in `.rudrai/rules/` are not supported in MVP. `.rudrai.yaml` may configure exclusions/suppressions, but all suppressions must be visible in outputs/events and can be ignored in strict mode. | STRIDE-style self-threat model with mitigations for rule tampering, output tampering, config abuse, and data leakage. |
| 6 | RESOLVED | Define rule pack and update integrity model | Rules are product IP and a supply-chain risk. | Built-in rules ship inside the Python package, versioned with the CLI/rule-pack release. MVP has no rule auto-update. Outputs include scanner version and rule-pack version. Signed remote rule updates are deferred until after the core scanner is stable. | Rule format, versioning, signing/verification, local custom rules, update channel, offline behavior. |
| 7 | RESOLVED | Define finding schema and severity/confidence model | Engineering needs stable fields before CLI, JSON, SARIF, and UI work. | Every finding must include separate required `severity` and `confidence` fields. Severity means impact if true; confidence means certainty based on evidence. This prevents weak single-signal matches from being treated as high-certainty critical findings. | Schema includes severity, confidence, rule ID, evidence, locations, remediation, fingerprints, mappings. |
| 8 | RESOLVED | Define false-positive suppression model | Noisy security tools get ignored or removed. | MVP suppressions are centralized in `.rudrai.yaml` only. Inline ignore comments are deferred. Suppressions require `rule_id`, path/glob, and reason; owner/expiry are optional. Suppressed findings remain visible in JSON/SARIF/events. `--strict` ignores suppressions for CI/security baselines. | `.rudrai.yaml`, inline ignores, strict mode, audit logging for suppressions, CI behavior. |
| 9 | RESOLVED | Define file discovery and scope rules | Scanner behavior depends on predictable target selection and exclusions. | MVP discovery is targeted to known high-risk agent/config/dependency files. It respects `.gitignore`, skips generated/vendor directories, does not follow symlinks by default, and supports `--include` / `--exclude` overrides. | File patterns, `.gitignore` behavior, generated/vendor/test handling, max file sizes, symlink policy. |
| 10 | RESOLVED | Define MCP audit model | MCP checks need structured parsing and least-privilege policy. | MVP MCP auditing is static-only. RudrAI parses MCP/config JSON and local command strings but never starts, connects to, or introspects live MCP servers. It flags unrestricted shell tools, broad filesystem roots, sensitive paths, insecure remote endpoints, and suspicious local server commands. | Supported config formats, dangerous capabilities, filesystem/network policy, local command analysis. |
| 11 | RESOLVED | Define dependency/registry audit model | Registry lookups affect performance, reliability, privacy, and offline enterprise usage. | Default scans make no network calls. MVP parses dependency manifests locally and flags suspicious install patterns, direct URL dependencies, risky scripts, and package names found in agent instructions. npm/PyPI existence/freshness checks are opt-in only through a future/explicit connected flag such as `--check-registries`. | Decide default offline vs connected mode, cache TTL, npm/PyPI sources, failure mode, opt-in flags. |
| 12 | RESOLVED | Define cross-file reference analysis | Split payloads can evade single-file scanning. | MVP follows local file references only within the scan root, never executes referenced files, never fetches external URLs by default, and uses a bounded depth limit of 2 hops. External URLs are recorded and scored as references, not retrieved. | Reference resolution rules, local script follow behavior, depth limits, external URL handling. |
| 13 | RESOLVED | Define CLI UX and exit-code contract | CI/CD adoption requires stable behavior. | Primary command is `rudrai scan [path]`. Default CI failure threshold is `--fail-on high`, so unsuppressed `HIGH` and `CRITICAL` findings return exit code `1`. Medium/low findings do not fail by default. Operational/config errors use distinct non-security exit codes. `--strict` ignores suppressions. | Commands, flags, default output, JSON/SARIF output, exit codes, fail thresholds. |
| 14 | RESOLVED | Define SARIF and report integrity | Reports become security decision artifacts in CI. | MVP emits valid SARIF 2.1.0, stable finding fingerprints for deduplication, and SHA-256 report checksums. Cryptographic signing/HMAC verification is deferred until there is a backend, enterprise CI requirement, or mature key-management story. | SARIF 2.1.0 compliance level, checksums/signing, fingerprints, verification mode. |
| 15 | RESOLVED | Define audit/event schema | Future platform needs a bridge from CLI scans to central evidence. | Structured audit/event output is opt-in via `--events-file`, written as JSON Lines for future backend/platform ingestion. Normal CLI output stays clean. Events must not include full file contents. | Minimal JSON event schema for scan start/end, files, rules, findings, suppressions, errors. |
| 16 | RESOLVED | Define performance and concurrency plan | The spec claims sub-second or near-sub-second scanning without implementation detail. | MVP performance target applies only to offline default scanning. Target: scan 1,000 discovered candidate files in under 1.5 seconds on a typical developer machine, excluding opt-in registry checks and future ML/LLM deep-scan modes. | Benchmarks, repo profiles, concurrency approach, network exclusion from core scan SLA. |
| 17 | RESOLVED | Define test/evaluation corpus | Detection quality cannot be proven without known-good/known-bad examples. | MVP requires a versioned local fixture corpus before the spec is execution-ready. Corpus includes known-malicious, known-benign, MCP, dependency, split-payload, expected-output, and 1,000-file performance benchmark cases. | Corpus structure, Numa-style samples, benign docs, MCP fixtures, expected findings, regression harness. |
| 18 | RESOLVED | Define packaging and distribution | Installation approach affects enterprise adoption and security. | MVP distribution starts as a standard Python package for Python 3.10+ with a `rudrai` console script and `pipx install rudrai` as the preferred user install path after publication. Windows, macOS, and Linux are first-class CLI targets. Standalone binaries via PyInstaller/PyOxidizer are deferred until user demand justifies them. | pip/pipx/binary decision, release signing, supported OS/Python versions, upgrade behavior. |
| 19 | RESOLVED | Define Windows parity requirements | Existing examples are Linux/macOS-heavy but target developers may use Windows. | Windows parity is required for MVP. The scanner must normalize paths across Windows/macOS/Linux and include Windows-specific detections for credential paths, PowerShell execution/download patterns, and persistence mechanisms such as Task Scheduler, Registry Run keys, Startup folder, and PowerShell `$PROFILE`. | Windows credential paths, PowerShell patterns, persistence mechanisms, path normalization behavior. |
| 20 | RESOLVED | Produce final engineering execution spec outline | Engineering needs one coherent document, not disconnected PRD/review notes. | Created `RUDRAI_ENGINEERING_EXECUTION_SPEC.md` as the build handoff artifact. The tracker remains the decision log. The spec consolidates resolved decisions, deferred items, implementation phases, and acceptance checklist. | Final spec table of contents, ADR links, implementation phases, owners, and milestone checklist. |

## Current Active Item

### 20. Produce final engineering execution spec outline

**Decision needed:** What final document structure should turn these resolved decisions into one engineering execution spec?

**Recommended default:** Create a new execution spec file, separate from the tracker, with this structure:

- MVP scope and non-goals;
- architecture decisions/ADRs;
- scanner pipeline and file routing;
- detection tiers and rule model;
- finding schema and suppression model;
- CLI contract and output formats;
- event/report integrity model;
- performance and evaluation corpus requirements;
- packaging/platform support;
- implementation phases and acceptance checklist.

This becomes the handoff artifact engineers can build from, while the tracker remains the decision log.

**Questions to resolve:**

1. Should I create a separate `RUDRAI_ENGINEERING_EXECUTION_SPEC.md` file that consolidates all resolved decisions into the first implementation-ready spec?

**Resolution:** Created `RUDRAI_ENGINEERING_EXECUTION_SPEC.md` as the implementation-facing engineering execution spec. The tracker remains the decision log.

**Exit bar for this item:**

- Final spec filename selected.
- Table of contents accepted.
- Resolved tracker decisions consolidated.
- Open/deferred items called out explicitly.
- Engineering phase checklist included.

## Resolution Log

- 2026-09-20: Item 1 resolved. First engineering execution spec will focus on an offline-first local CLI scanner named `rudrai scan`. Backend and platform components are deferred to later phases.
- 2026-09-20: Item 2 resolved. MVP scanner will use Python 3.10+. Integration with any future backend/platform will happen through JSON, SARIF, and structured event files; no backend component is included in the first engineering execution spec.
- 2026-09-20: Item 3 resolved. Detection routing is file-type based. Tier 1 deterministic heuristics run on discovered candidate files, but Tier 1 does not gate Tier 2. Tier 2 intent/camouflage analysis runs on all agent instruction files by default, and applicable Tier 3/Tier 4 checks run based on dependency or MCP/tool config file type.
- 2026-09-20: Item 4 resolved. MVP Tier 2 will be an offline, explainable heuristic analyzer using signal clusters for purpose mismatch, stealth language, authority override, credential intent, execution intent, and persistence intent. External LLM/API analysis and bundled ML models are deferred to a future optional `--deep-scan` mode.
- 2026-09-20: Item 5 resolved. MVP will not support local custom rules. Built-in versioned rules ship with the scanner package. Local `.rudrai.yaml` can configure exclusions/suppressions only, and suppressions must be visible in JSON/SARIF/events with a strict mode available to ignore them.
- 2026-09-20: Item 6 resolved. MVP has no rule auto-update mechanism. Built-in rules ship inside the Python package, are versioned with the scanner/rule-pack release, and scanner/rule-pack versions must appear in outputs. Signed remote rule updates are deferred.
- 2026-09-20: Item 7 resolved. Findings require separate `severity` and `confidence` fields. Severity represents impact if true; confidence represents certainty based on the evidence. The finding schema must avoid escalating weak, single-signal matches into high-certainty critical findings.
- 2026-09-20: Item 8 resolved. MVP suppressions are centralized in `.rudrai.yaml` only. Suppressions require `rule_id`, path/glob, and reason, with optional owner/expiry. Suppressed findings must remain visible in JSON/SARIF/events. `--strict` ignores all suppressions for CI/security baselines. Inline ignore comments are deferred.
- 2026-09-20: Item 9 resolved. MVP discovery is targeted to known high-risk files by default: agent instruction files, MCP configs, and dependency manifests. It respects `.gitignore`, skips generated/vendor directories, avoids following symlinks by default, and provides `--include` / `--exclude` overrides.
- 2026-09-20: Item 10 resolved. MVP MCP auditing is static-only. RudrAI parses known MCP/config files and local command strings but never starts, connects to, or introspects live MCP servers. It flags risky shell capabilities, broad filesystem access, sensitive paths, insecure remote endpoints, and suspicious local server commands.
- 2026-09-20: Item 11 resolved. Default scans make no network calls. Dependency auditing is local/offline by default: parse manifests, flag suspicious install patterns, direct URL dependencies, risky scripts, and package names found in agent instructions. npm/PyPI registry verification is opt-in only through a connected flag such as `--check-registries`.
- 2026-09-20: Item 12 resolved. MVP follows local file references only within the scan root, with a default depth limit of 2 hops. Referenced files are scanned but never executed. External URLs are recorded and scored as references but never fetched by default.
- 2026-09-20: Item 13 resolved. CLI default is `rudrai scan [path]` with human-readable terminal output and machine-readable JSON/SARIF modes. Default failure threshold is `--fail-on high`, so unsuppressed `HIGH` and `CRITICAL` findings return exit code `1`; medium/low findings do not fail CI by default. Operational/config failures use distinct non-security exit codes, and `--strict` ignores suppressions.
- 2026-09-20: Item 14 resolved. MVP emits valid SARIF 2.1.0, stable finding fingerprints for deduplication, and SHA-256 report checksums. Cryptographic signing/HMAC verification is deferred until there is a backend, enterprise CI requirement, or mature key-management story.
- 2026-09-20: Item 15 resolved. Structured audit/event output is opt-in via `--events-file`, written as JSON Lines for future backend/platform ingestion. Normal CLI output remains clean, and events must never include full file contents.
- 2026-09-20: Item 16 resolved. MVP performance target applies only to offline default scanning: scan 1,000 discovered candidate files in under 1.5 seconds on a typical developer machine. Opt-in registry checks and future ML/LLM deep-scan modes are excluded from this SLA.
- 2026-09-20: Item 17 resolved. MVP requires a versioned local fixture corpus before the engineering spec is execution-ready. It includes known-malicious fixtures such as Numa-style poisoned skills and split payloads, known-benign fixtures such as DevOps/SSH docs, MCP and dependency fixtures, expected JSON outputs/snapshots, and a 1,000-file benchmark fixture.
- 2026-09-20: Item 18 resolved. MVP distribution starts as a standard Python package for Python 3.10+ with a `rudrai` console script. Preferred published install path is `pipx install rudrai`. Windows, macOS, and Linux are first-class CLI targets. Standalone PyInstaller/PyOxidizer binaries are deferred.
- 2026-09-20: Item 19 resolved. Windows parity is required for MVP. RudrAI must normalize paths across Windows/macOS/Linux and include Windows-specific detections for credential paths, PowerShell execution/download patterns, Task Scheduler, Registry Run keys, Startup folder, and PowerShell `$PROFILE`.
- 2026-09-20: Item 20 resolved. Created `RUDRAI_ENGINEERING_EXECUTION_SPEC.md` as the implementation-facing build handoff artifact. `ENGINEERING_EXECUTION_SPEC_TRACKER.md` remains the decision log.
