# MVP-1 implementation status

The first build slice implements the offline scanner and its packaging boundary.

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

