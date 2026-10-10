# MVP-1 implementation status

The first build slice implements the offline scanner and its packaging boundary.

For milestone status, verification history and instructions for resuming in a new
session, start with the [project tracker](PROJECT_TRACKER.md).

## Architecture hardening: first implementation batch

The approved review is now tracked in [architecture decisions](ARCHITECTURE_DECISIONS.md).
This batch adds explicit partial coverage and exit code 3, pre-resolution
symlink/junction checks, bounded reads/batches/retained text, nested gitignore and
include precedence, matching JSON/YAML config validation, config digests,
malformed JSON/TOML failure handling, TOML dependency groups, multiline execution
and Windows patterns, atomic output, detached byte checksums and `rudrai verify`.
JSONL events now carry schema versions and a shared per-scan ID.

Validation on Windows/Python 3.11: 21 tests executed, 20 passed and one symlink
test skipped because host privileges do not allow creating a link. The benign
1,000-file benchmark measured approximately 0.8 seconds. CI is configured for
Windows/macOS/Linux and Python 3.10–3.13, including wheel/pipx smoke checks;
those remote jobs have not yet been executed here.

The full approved backlog is **not complete**. Corpus precision gates,
context-aware scoring, MCP graph/field audits, SARIF schema validation, redaction,
streaming events, and attack-heavy benchmarks remain open. See the decisions
document for the review-by-review disposition and residual security limitations.

## Evaluation corpus and contextual scoring: second implementation batch

`tests/corpus/v1` is now a versioned, labeled regression corpus. It records the
complete expected findings (rule, severity, confidence, file and line) for benign
and malicious agent instructions, Windows persistence, obfuscation, MCP,
dependency and split-payload cases. The harness enforces a zero false-positive
budget for its benign cases, requires every designated critical case to remain
critical, and checks finding fingerprint stability across repeated scans.

Tier 2 now only combines intent signals found in the same 12-line instruction
block, and ignores command, URL, override and intent matches that are explicitly
negated or Markdown-quoted. Clustered findings expose a `nearby_signal_cluster`
signal. This is a precision improvement, not a claim of broad calibration: a
larger representative corpus and measured precision/recall remain required.

Implemented:

- `rudrai scan [path]` with stable exit codes and threshold handling.
- Targeted discovery, `.gitignore`, built-in generated/vendor exclusions,
  include/exclude globs, file-size limits, and no symlink following.
- Tier 1 execution, credential, obfuscation, persistence, and Windows patterns.
- Tier 2 deterministic intent/camouflage signal clustering for every instruction file.
- Static MCP and offline dependency audits.
- Two-hop local reference analysis; external references are recorded but not fetched.
- Central suppressions, strict mode, stable fingerprints, JSON, SARIF 2.1.0,
  report checksums, and opt-in JSONL events.
- Standard Python package, `pipx` path, composite GitHub Action, test matrix,
  package build, and trusted-publishing workflow skeleton.

Deliberately deferred:

- Connected package-registry verification. The reserved flag returns exit code 2.
- External or local ML/LLM analysis.
- Custom rule packs, rule auto-update, inline suppressions, and signed reports.
- Backend services, dashboards, identity/RBAC, runtime interception, and standalone binaries.

