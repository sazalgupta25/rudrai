# Architecture decisions and review conformance

Status: accepted implementation direction; hardening is in progress, not a release approval.

## ADR-001: scanner and platform boundary

The MVP is an offline Python CLI running as the invoking operating-system user.
It reads untrusted local text; it never runs inspected commands, imports project
code, contacts registries, or sends source to a model. All instruction files pass
through deterministic Tier 1 and heuristic Tier 2, irrespective of earlier results.
MCP and dependency audits are static file-type-specific passes.

Java/Spring/Oracle remains a future platform direction, not an MVP dependency.
The current integration contract is versioned JSON, SARIF 2.1.0, and JSONL events.
Future platform consumers must reject incomplete scan status, retain exclusions
and suppression metadata, and design identity, tenancy, authenticated ingestion,
retention and access control before introducing a backend. No API is implemented.

Rules ship as trusted Python package code with a versioned rule pack; updates
are explicit package upgrades. There are no executable custom YAML rules or
automatic rule downloads. Package provenance remains the operator's responsibility.

## STRIDE self-threat model

| Threat | Implemented mitigation | Residual risk / deferred work |
|---|---|---|
| Spoofing | Explicit local source/wheel deployment | Trusted provenance and release signing are not implemented |
| Tampering | Config digest, visible exclusions/suppressions, strict suppression bypass | Digest is not authentication; strict does not remove path exclusions |
| Repudiation | Schema-versioned JSONL with per-scan ID, completeness metadata | Local events are mutable, not an immutable audit store |
| Disclosure | Offline scan; no telemetry or classifier API | Finding evidence and local paths can contain secrets; redaction remains required |
| Denial of service | Bounded reads, 10,000 candidates, 64 MiB retained text, bounded events/coverage | No wall-clock deadline; traversal/regex/input complexity still need adversarial tests |
| Elevation of privilege | No project execution; reject symlinks/reparse points before resolution | Concurrent filesystem replacement races are not fully prevented; scan a stable snapshot |

Each file defaults to a 1 MiB read limit (configurable to 100 MiB). The total
retained UTF-8 text budget is 64 MiB, with at most 10,000 analyzed files and
100,000 buffered events. A limit hit is incomplete coverage / operational failure,
not a clean scan. Resources are bounded but not a promise of a fixed RSS ceiling.
Report/event writes publish through a same-directory temporary file and replace;
report plus checksum publication is not a single transaction. `rudrai verify`
compares exact report bytes to a detached checksum. An attacker able to change both
files can bypass it; HMAC/signing requires a separately approved key-management design.

## Review dispositions

| Finding | MVP disposition |
|---|---|
| F-01 | Heuristic Tier 2 chosen; representative precision/recall corpus remains open |
| F-02 | Threat model above; config audit and boundaries implemented, signatures deferred |
| F-03 | Standalone Python scanner with artifact boundary; Java platform deferred |
| F-04 | No model or network service invoked |
| F-05 | OS user identity; artifact authentication and backend RBAC deferred |
| F-06 | Registry flag rejected explicitly; no registry lookups |
| F-07 | Multiline and Windows patterns expanded; language/encoding evasion remains a limitation |
| F-08 | Every instruction file receives Tier 2, independent of Tier 1 |
| F-09 | Detached byte checksum and verify implemented; signing and schema validation still open |
| F-10 | Rules versioned with package; explicit upgrade, no auto-update |
| F-11 | Bounded read batches/thread workers; small benign benchmark only, broader workload open |
| F-12 | Two-hop instruction references with missing/out-of-root failure; MCP graph still open |
| F-13 | Heuristic analysis only, no ML claim |
| F-14 | Versioned events and scan IDs; streaming/redaction remains open |
| F-15 | Backend prerequisites documented, no backend implementation |
| F-16 | Confidence/signals emitted; calibration, contextual scoring and filtering remain open |
| F-17 | Nested gitignore, include/exclude, central suppressions; inline/severity overrides deferred |
| F-18 | Wheel/pipx distribution chosen; standalone binaries deferred |
| F-19 | No telemetry; any future telemetry requires explicit consent |
| F-20 | Windows credential/profile/registry patterns expanded; parity suite still needed |

## Remaining approved implementation work

- B02/B06: varied labeled malicious/benign corpus, nearby signal clustering,
  quote/negation context, confidence calibration and measurable critical precision.
- B04/B05: adversarial resource tests, complete policy provenance, race-safe reads,
  further gitignore parity and duplicate/config syntax tests.
- B07: MCP supported-field validation and local command graph, cycle/depth reporting.
- B08: dependency shape validation, requirements includes, exact TOML locations.
- B09/B10: official SARIF schema validation, redaction, streaming events, scan ID in reports.
- B11/B12: attack-heavy benchmarks, wheel/pipx lifecycle checks and actual multi-OS CI results.

Do not interpret a clean synthetic fixture as evidence of 95% critical precision.
