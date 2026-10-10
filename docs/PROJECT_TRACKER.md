# RudrAI project tracker and session handoff

Last updated: 2026-10-10. Canonical checkout: `C:\sazal\rudrai`.

This is the primary development progress and session-resumption record. The
[execution spec](RUDRAI_ENGINEERING_EXECUTION_SPEC.md) defines scope and acceptance;
the [decision tracker](ENGINEERING_EXECUTION_SPEC_TRACKER.md) records design decisions,
not delivered milestones. [Implementation status](IMPLEMENTATION_STATUS.md) summarizes
features; [architecture decisions](ARCHITECTURE_DECISIONS.md) record review dispositions
and residual risks; [deployment](DEPLOYMENT.md) contains operational instructions.

## Current checkpoint

- Milestone: MVP-1 offline CLI; initial build implemented, architecture hardening in progress.
- User approved implementation of the architecture hardening backlog.
- Last observed commit: `868157c` — initial build version rudrai 0.1.0 (rules 2026.10.0).
- First hardening batch is present but **uncommitted**. New sessions must inspect
  current Git state; the commit above does not include that batch.
- Release readiness: **not accepted**. Cross-platform CI, representative quality
  gates, complete audit hardening and deployment verification remain outstanding.
- Current recommended work: expand B02 beyond corpus v1 and use its results to
  measure B06 calibration. The first corpus and context-scoring implementation is
  present in the working tree; it is not release acceptance evidence.
- This tracker update changes documentation only; tests were not rerun for it.

## Status conventions

`NOT STARTED`: no implementation recorded. `IN PROGRESS`: some work exists but
acceptance remains open. `IMPLEMENTED`: code/docs exist, verification incomplete.
`VERIFIED`: specified acceptance has evidence on named environments. `BLOCKED`:
external requirement prevents progress. `DEFERRED`: outside current scope.
Do not treat resolved design decisions, configured CI jobs or skipped tests as verified work.

## Milestone board

| ID | Milestone / spec phase | Current status | Remaining exit evidence |
|---|---|---|---|
| M01 | Package, console command and CLI (phase 1) | IMPLEMENTED; source tests pass locally | Built-wheel console smoke and lifecycle evidence across supported platforms |
| M02 | Discovery and config (phase 2) | IN PROGRESS | Adversarial limits, policy/ignore parity, config syntax and filesystem boundary tests |
| M03 | Rules and findings (phase 3) | IN PROGRESS | Labeled corpus, contextual signal scoring and confidence/false-positive gates |
| M04 | MCP, dependency and cross-file audits (phase 4) | IN PROGRESS | Supported MCP fields and graph, manifest shape validation, reference cycles/depth and Windows parity |
| M05 | Reports, events and CI (phase 5) | IN PROGRESS | Official SARIF schema validation, redaction, streaming audit and remote CI results |
| M06 | Evaluation and performance (phase 6) | IN PROGRESS | Representative expected outcomes, precision measurement and attack-heavy performance |
| M07 | Local deployment and release readiness | IN PROGRESS | Wheel/pipx install/reinstall/upgrade/uninstall with current dependencies, offline wheelhouse and multi-OS proof |

## Approved hardening backlog

These IDs are the approved implementation workstreams, not newly approved features.

| ID | Workstream | Status / delivered portion | Remaining acceptance |
|---|---|---|---|
| B01 | Architecture conformance and STRIDE | IMPLEMENTED: ADR and F-01–F-20 dispositions | Keep dispositions tied to actual verification; no release approval implied |
| B02 | Versioned evaluation corpus | IN PROGRESS: labeled corpus v1 with exact expected findings, critical and false-positive gates | Broaden representative labels and measure precision/recall against a defined false-positive budget |
| B03 | Scan completeness | IMPLEMENTED: partial metadata, exit 3, exclusion distinction, strict suppression semantics | Broaden regression evidence for all incomplete paths and all report formats |
| B04 | Filesystem/resource boundaries | IN PROGRESS: pre-resolution link checks, read/batch/text/event bounds | Junction/link tests where privileges permit, adversarial resources, stable-snapshot/race limitations and traversal coverage |
| B05 | Discovery/config correctness | IN PROGRESS: nested gitignore/include precedence and shared JSON/YAML validation, config digest | Policy provenance, reference-policy parity, duplicates, syntax/type and further gitignore parity tests |
| B06 | Detection/explainability | IN PROGRESS: multiline execution, Windows patterns, local signal clusters, quote/negation context | Confidence calibration and representative precision evidence |
| B07 | MCP/reference graph | IN PROGRESS: static audit and two-hop instruction references | Supported-field validation; local MCP commands; explicit graph edges, missing/blocked references, cycles/depth |
| B08 | Dependency audit | IN PROGRESS: JSON/TOML parse failures, TOML dependency groups | Robust shape validation, requirements includes and exact finding locations |
| B09 | SARIF/integrity | IN PROGRESS: URI escaping, exact-byte sidecar and `rudrai verify` | Official SARIF schema validation and broader integrity regressions; checksum is not authentication |
| B10 | Audit/output handling | IN PROGRESS: versioned per-scan event IDs, bounded events, atomic writes and error handling | Report/event scan-ID linkage, streaming, redaction, reference/status/suppression coverage and collision tests |
| B11 | CI/distribution/performance | IN PROGRESS: multi-OS/Python matrix and wheel/pipx smoke configured | Actual matrix results, lifecycle/offline-install evidence and benign plus attack-heavy benchmarks |
| B12 | Documentation and readiness | IN PROGRESS: status, deployment, ADR and handoff tracker | Update each completed workstream with evidence; reconcile acceptance before release |

## Verification ledger

Historical observations below refer to the first hardening batch in the canonical
working tree, not a committed/released artifact. Re-run when source or dependencies change.

| Date | Environment / check | Observed result | Limitation |
|---|---|---|---|
| 2026-10-10 | Windows, Python 3.11; `python -m unittest discover -s tests -v` | 21 executed: 20 passed, 1 skipped | Symlink creation privileges unavailable; source run supplied `pathspec` from worktree `.test-deps` through `PYTHONPATH` |
| 2026-10-10 | `python scripts/benchmark.py`; 1,000 small benign instruction files | 0.764 seconds; 1,000 scanned, no findings | Synthetic benign workload only; not an adversarial benchmark or precision measurement |
| 2026-10-10 | Canonical `git diff --check` | No whitespace errors | Does not validate runtime, security or untracked files |
| 2026-10-10 | CI: Windows/macOS/Linux, Python 3.10–3.13 | Configured, not observed passing | Remote jobs were not run/inspected in this session |
| 2026-10-10 | Current hardened wheel/pipx and air-gapped installation | NOT VERIFIED | Earlier MVP installation evidence must not be reused for changed runtime dependencies |
| 2026-10-10 | Windows, Python 3.11; corpus v1 plus full unit suite | 23 executed: 22 passed, 1 skipped; corpus benign false positives 0; 1,000-file benchmark 0.771 seconds | Corpus v1 is small and local; symlink privileges unavailable; no cross-platform or representative precision evidence |

For future evidence record date, task/milestone ID, commit or working-tree identity,
OS/Python/dependency versions, exact command, outcome, skips/failures and artifact
location or CI run URL. Store redacted evidence only; avoid secrets/full scanned content.

## Resume a new session

1. Open `C:\sazal\rudrai`. Do not assume a Codex worktree is canonical or up to date.
2. Read this tracker, implementation status and architecture decisions, then the
   relevant execution-spec/deployment sections. Check applicable `AGENTS.md` files.
3. Inspect Git status, branch, last commit and existing diffs. Preserve uncommitted
   changes. Do not reset, commit, publish or deploy merely to create a checkpoint.
4. Confirm the selected backlog item and its acceptance criteria. Start with B02
   unless the user chooses another remaining development, testing or deployment item.
5. Set up dependencies in a virtual environment using the deployment runbook;
   install from the local checkout. Do not rely on another session's `.test-deps`.
6. Establish a fresh baseline with tests and the relevant benchmark. Record failures
   or missing prerequisites before treating historical results as current evidence.
7. Implement only approved scope; verify in proportion to risk. Coordinate any
   worktree-to-canonical transfer and inspect canonical changes before overwriting.
8. Update backlog/milestone status, verification ledger and the checkpoint below.
   Keep implementation status and deployment instructions consistent with changes.

### Suggested starting request

Work in the canonical checkout `C:\sazal\rudrai`. Read `docs/PROJECT_TRACKER.md`,
`docs/IMPLEMENTATION_STATUS.md` and `docs/ARCHITECTURE_DECISIONS.md`. Inspect existing
uncommitted changes and preserve them. Resume B02 evaluation-corpus work from the
approved backlog, establish a fresh test baseline, and record acceptance evidence
and the next handoff state. Do not publish or deploy without an explicit request.

## Session checkpoint log

| Date | Delivered checkpoint | Next work / pending verification |
|---|---|---|
| 2026-10-10 | Initial hardening batch: coverage failures, filesystem/resource boundaries, discovery/config/manifest improvements, checksums/atomic outputs, event metadata and CI matrix | B02 first, then B06; broader graph, schema, redaction, resource, installation and cross-platform evidence remain |
| 2026-10-10 | Added project tracker and documentation entry links; runtime unchanged | Baseline should be rerun in a properly installed development environment before the next implementation batch |
| 2026-10-10 | B02 corpus v1 and B06 local context scoring added; labeled exact outcomes, critical/false-positive/fingerprint gates and nearby/negated/quoted context handling | Expand corpus and calibrate confidence with representative data; complete B07–B12 verification backlog |

Append a row after each meaningful session: date, affected IDs/files, completed
acceptance evidence, incomplete work, blockers, repository state and exact next step.

## Explicitly deferred

Connected registries, ML/LLM analysis, HMAC/signing/key management, automatic/custom
rule updates, telemetry, backend/RBAC/audit-store services, runtime interception,
dashboards and standalone binaries remain outside this approved hardening scope.
