# RudrAI Architecture Review Board — Joint Panel Report

**Review Date**: 2026-09-13
**Documents Reviewed**: [RUDRAI_REQUIREMENTS_SPEC.md](file:///c:/sazal/rudrai/RUDRAI_REQUIREMENTS_SPEC.md) · [MVP_SPEC_AGENT_SCANNER.md](file:///c:/sazal/rudrai/MVP_SPEC_AGENT_SCANNER.md)

**Panel**:
- **[SA]** — Principal Security Architect
- **[AI]** — Agentic AI Systems Architect
- **[CE]** — Staff Cloud-Native Engineer

---

## 1. Executive Summary

- **Overall Maturity**: The spec is a strong *product vision* document, but it currently sits at the level of a well-argued pitch deck with architectural sketches — it is **not yet an implementable architecture spec** that a security or platform review board could approve.
- **Biggest Architectural Strength**: The 3-tier detection pipeline (Deterministic → Semantic → Registry) is a genuinely well-designed hierarchy. It avoids the common trap of over-relying on LLM classifiers for deterministic pattern matching and correctly layers semantic analysis on top. [SA, AI agree]
- **Biggest Risk (AI)**: The Tier 2 Semantic Intent Classifier is the spec's single most critical component and its least specified. It is described in four bullet points. A false-negative here is a missed CRITICAL. A false-positive kills adoption. There is **zero detail** on what model powers it, what training data it uses, what latency it adds, how it's updated, or how adversaries evade it.
- **Biggest Risk (SA)**: The spec **has no threat model of RudrAI itself**. Every section describes what RudrAI detects in *other* systems, but there is no analysis of how RudrAI's own rule packs, update mechanism, registry calls, and output can be attacked. A security tool that ships without its own threat model is professionally embarrassing.
- **Biggest Risk (CE)**: The spec says "Python 3.10+" with a 10-day build timeline for a product described as a platform-grade enterprise security tool. There is a **complete absence of backend/cloud architecture** — no API server, no persistent storage, no multi-user model, no telemetry aggregation — yet the requirements spec (Tier 1 Foundation) calls for "Immutable Audit Store" and "Multi-Tenant RBAC." These two documents are architecturally disconnected.
- **Strategic Observation**: The MVP's positioning as a pure CLI scanner is sound — it avoids the cold-start problem of requiring infra changes. But the requirements spec's Tier 1 Foundation (audit store, RBAC, event schema) is never referenced by the MVP spec. There is no bridge document.
- **Stack Question**: The requirements spec header says "Java/Spring Boot microservices, Oracle-backed." The MVP spec says "Python 3.10+, click, typer, pydantic." These directly contradict. Which is it? This must be resolved before any engineering begins. [All three panelists flag this]

---

## 2. Detailed Findings Table

| # | Area | Severity | Issue | Recommendation | Panelist |
|---|------|----------|-------|----------------|----------|
| F-01 | **Agentic AI Threat Surface** | **CRITICAL** | **Tier 2 Semantic Classifier is a black box.** No model specified (local LLM? API call to OpenAI? Fine-tuned transformer? Heuristic NLP?). No latency budget. No false-positive/negative targets. No training/eval data strategy. No adversarial evasion analysis. This is the component that distinguishes RudrAI from a regex grep wrapper. | Produce a dedicated Tier 2 design doc: model selection, inference latency SLA (must fit within the <500ms total budget), offline-vs-API tradeoff, eval dataset with precision/recall targets (≥95% precision for CRITICAL), adversarial red-team test plan. | [AI] |
| F-02 | **Agentic AI Threat Surface** | **CRITICAL** | **No self-protection threat model.** The YAML rule packs are loaded from disk. A poisoned `.rudrai.yaml` or custom rule in `rules/` could disable detections, whitelist malicious patterns, or cause RudrAI to report false "clean" results. A compromised rule pack is a supply-chain attack on the security tool itself. | Apply STRIDE to RudrAI itself. Specifically: rule packs must be signed and verified; `.rudrai.yaml` exclusions must be logged and auditable; the scanner must detect attempts to disable its own detections. Add a "self-integrity" check mode. | [SA] |
| F-03 | **Architecture** | **CRITICAL** | **Stack contradiction.** Requirements spec envisions Java/Spring Boot/Oracle platform. MVP spec specifies Python/click/pydantic CLI. No document reconciles these. If the platform is Java and the scanner is Python, what is the integration model? gRPC? REST? Subprocess? Shared DB? | Decide: (a) MVP is a standalone Python CLI that is **not** part of the Java platform (it feeds SARIF artifacts into it), or (b) the Java/Spring vision is aspirational and the actual platform is Python-native. Document the answer. If (a), specify the integration contract now. | [CE] |
| F-04 | **Agentic AI Threat Surface** | **HIGH** | **No model/data supply chain risk analysis for the scanner itself.** If Tier 2 calls an external LLM API, then RudrAI itself becomes vulnerable to: model poisoning, prompt injection against the classifier, API key exfiltration, data leakage of scanned workspace content to third-party model providers. | Specify: (a) Does the Tier 2 classifier call an external API? If yes, what data is sent? Is it PII-free? (b) What happens when the API is unavailable — fail-open (dangerous) or fail-closed (blocks CI)? (c) Is there an air-gapped/offline mode? | [AI] |
| F-05 | **Security Architecture** | **HIGH** | **No authentication, authorization, or identity model anywhere.** The MVP CLI runs as the invoking user. But: who can modify rule packs? Who can add exclusions in `.rudrai.yaml`? In CI/CD, what service identity runs the scan? Are findings signed to prevent tampering between scan and report consumption? | For MVP: at minimum, sign SARIF output with an HMAC so consumers can verify integrity. For platform: design agent-identity vs. user-identity vs. service-identity model before building Tiers 1-4 of the requirements spec. | [SA] |
| F-06 | **Architecture** | **HIGH** | **Registry calls (PyPI/npm) in a CI scanner introduce external dependency, latency, and security risk.** The spec claims <1.5s for 1,000 files but doesn't account for network round-trips. Registry calls can fail, be rate-limited, or be MITM'd. A malicious DNS response could make a truly hallucinated package appear legitimate. | (a) Cache registry responses with configurable TTL. (b) Support an offline mode with a pre-fetched registry snapshot. (c) Pin registry endpoints and verify TLS certificates explicitly. (d) Separate the registry check into an opt-in flag (`--check-registries`) so core scanning remains fully offline and deterministic. | [CE] |
| F-07 | **Agentic AI Threat Surface** | **HIGH** | **Evasion via encoding/language is trivially achievable.** Tier 1 relies on regex for patterns like `curl | bash`, but adversaries will use synonyms, multi-line splitting, indirect references ("run the command stored in variable X"), or non-English languages. The spec acknowledges Unicode tricks but doesn't address semantic-level evasion of Tier 1. | Explicitly define Tier 1 as a **high-confidence, low-coverage** fast path. All files should pass through Tier 2 regardless of Tier 1 results (not just "flagged/suspicious" files). The current architecture diagram shows Tier 2 only receives Tier 1 flagged items — this means sophisticated attacks bypass semantic analysis entirely. | [AI] |
| F-08 | **Architecture** | **HIGH** | **Detection pipeline flow is architecturally incorrect.** The diagram (§4) shows: Tier 1 → if clean, skip to Tier 3 registry check; if suspicious, route to Tier 2. This means a file that passes Tier 1 regex *never* gets semantic analysis. A well-crafted attack without any regex-matchable indicators would be invisible. | **Redesign the pipeline**: Tier 1 (fast heuristics, all files) → Tier 2 (semantic analysis, all files that contain agent instructions) → Tier 3 (registry, dependency files only) → Tier 4 (MCP audit, config files only). Route by file type, not by Tier 1 outcome. | [AI, SA agree] |
| F-09 | **Security Architecture** | **HIGH** | **SARIF output integrity is unaddressed.** In a CI/CD pipeline, the SARIF file is the security decision artifact. If an attacker can modify the SARIF between generation and consumption (e.g., in a shared `/tmp` or artifact store), they can suppress findings. | Sign SARIF output. Emit a SHA-256 checksum. Support `--verify` mode on the consuming side. GitHub's code scanning API supports signed SARIF — use it. | [SA] |
| F-10 | **Gaps** | **HIGH** | **No versioning or update strategy for rule packs.** Rules are the core IP. How are they distributed? How are new detection signatures shipped? Is there an auto-update? If so, that's an attack surface. If not, stale rules degrade value. | Design a rule distribution model: (a) rules ship with the CLI binary (versioned together), (b) rules are fetched from a signed registry (like ClamAV), or (c) rules are a separate pip package. Specify update cadence and integrity verification. | [SA, CE] |
| F-11 | **Scalability** | **MEDIUM** | **No concurrency or parallelism model.** For 1,000 files in <1.5s, the scanner needs to parallelize file I/O and regex matching. Python's GIL makes this nontrivial. No mention of `asyncio`, `multiprocessing`, thread pools, or batch processing strategy. | Specify: use `multiprocessing.Pool` or `concurrent.futures.ProcessPoolExecutor` for CPU-bound regex/AST parsing. Use `asyncio` for I/O-bound registry calls. Benchmark the 1,000-file target on a real workspace (agent projects with large `node_modules` excluded). | [CE] |
| F-12 | **Agentic AI Threat Surface** | **MEDIUM** | **No handling of multi-file attack chains.** The Numa attack was a single-file exploit, but real-world attacks may split payloads across multiple files (e.g., SKILL.md references a separate `.sh` script, or an MCP config points to a local tool that contains the payload). The scanner evaluates files in isolation. | Add cross-file reference resolution: if a skill/rule references an external file or URL, follow the reference (within the scanned workspace) and analyze the target. Flag dangling external references as suspicious. | [AI] |
| F-13 | **Gaps** | **MEDIUM** | **"Semantic Intent Classifier" suggests ML, but the 10-day timeline and zero-dependency goal contradict this.** A meaningful semantic classifier requires either (a) an LLM API call (adds latency, cost, external dependency) or (b) a local model (adds binary size, contradicts "zero-dependency"). The spec doesn't reconcile this tension. | Resolve explicitly: MVP Tier 2 can be a **heuristic NLP classifier** (keyword co-occurrence, TF-IDF mismatch scoring between title/headers and body directives) — no ML required. Reserve true ML/LLM classification for v1.1. This keeps the <500ms and zero-external-dependency promises. | [AI, CE agree] |
| F-14 | **Security Architecture** | **MEDIUM** | **Audit logging is mentioned in the requirements spec (Tier 1: "Immutable Event & Audit Store") but completely absent from the MVP spec.** If the MVP doesn't emit structured audit events, retrofitting them later is painful. | Even the CLI MVP should emit a structured JSON event log (scan start, files discovered, rules evaluated, findings, scan end) to stdout or a file. This becomes the foundation for the future audit store. Design the schema now. | [SA] |
| F-15 | **Architecture** | **MEDIUM** | **The requirements spec's Tier 1 Foundation (event schema, RBAC, audit store) has no corresponding technical design.** It's listed as a box in an ASCII diagram but has no schema, no API, no data model. | This is acceptable for a vision document, but flag it: Tier 1 Foundation must be designed **before** Stage 2 (Local Shield) begins, because the shield needs to emit events into the audit store. Don't let Stage 2 start without Tier 1 design. | [CE] |
| F-16 | **Agentic AI Threat Surface** | **MEDIUM** | **No confidence scoring or explainability model for findings.** The spec shows severity (CRITICAL/HIGH/MEDIUM/LOW) but not confidence. A regex match on `~/.ssh` in a legitimate SSH documentation file would be a false positive. Without confidence scoring, noisy results kill adoption. | Add a confidence dimension: `{HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, LOW_CONFIDENCE}` orthogonal to severity. Tier 1 regex matches without Tier 2 corroboration = MEDIUM_CONFIDENCE. Tier 1 + Tier 2 corroboration = HIGH_CONFIDENCE. Allow `--min-confidence` filtering. | [AI] |
| F-17 | **Gaps** | **MEDIUM** | **`.gitignore` is the only exclusion mechanism mentioned.** Enterprise repos have complex layouts. What about: monorepo structures, vendored dependencies, generated files, test fixtures that intentionally contain attack patterns (for red team testing)? | Support a `.rudrai.yaml` exclusion config (already mentioned but not specified). Define: path exclusions, rule exclusions per-path, severity overrides, and "known-good" annotations (inline comments like `# rudrai:ignore SAI-001`). | [SA] |
| F-18 | **Architecture** | **LOW** | **PyInstaller/PyOxidizer binary distribution is mentioned but has known issues**: antivirus false positives, large binary sizes (~50-100MB), and platform-specific build complexity. | Evaluate `shiv` (Twitter's self-contained Python zip app) or `pipx` as lighter distribution alternatives. For enterprise, consider publishing to private PyPI. Reserve PyOxidizer for cases where Python cannot be assumed. | [CE] |
| F-19 | **Gaps** | **LOW** | **No telemetry or usage analytics model.** For a developer tool, understanding adoption (scan frequency, finding categories, false-positive rates) is critical for product iteration. | Add opt-in anonymous telemetry (scan count, finding distribution, CLI version) with explicit consent. Follow Homebrew/VS Code telemetry patterns. Never transmit file contents or paths. | [CE] |
| F-20 | **Agentic AI Threat Surface** | **LOW** | **No mention of Windows-specific attack vectors.** The spec is Linux-centric (`.bashrc`, `~/.ssh`). Windows developers using Cursor/Claude Code face different persistence mechanisms (Task Scheduler, Registry Run keys, PowerShell profiles, `$PROFILE`). | Expand Tier 1 heuristics to include Windows-native persistence and credential paths: `$env:USERPROFILE\.ssh`, `%APPDATA%`, Registry `HKCU\...\Run`, PowerShell `$PROFILE`, Windows Credential Manager references. | [AI] |

---

## 3. Top 5 Prioritized Recommendations

### Recommendation 1: Fix the Detection Pipeline Architecture (Effort: S)
**Rationale**: Finding F-08 is an architectural flaw that would let sophisticated attacks bypass semantic analysis entirely. The current flow routes "clean" Tier 1 files away from Tier 2. This must be inverted: **all agent instruction files** (skills, rules, configs) must pass through Tier 2 regardless of Tier 1 results. Tier 1 serves as a fast "definitely malicious" early-exit, not as a gate.

> [!CAUTION]
> **[AI] and [SA] consider this the most important single fix.** Without it, the scanner's headline feature (semantic intent mismatch detection — the exact thing that catches Numa) can be trivially bypassed by removing regex-matchable patterns.

**Concrete change**: Modify the pipeline diagram and implementation plan:
```
All files → Tier 1 (fast heuristics, flag obvious threats)
         → Tier 2 (semantic analysis on ALL agent instruction files, not just Tier 1 flagged)
         → Tier 3 (registry checks on dependency files only)
         → Tier 4 (MCP audit on config files only)
         → Merge & deduplicate findings
```

---

### Recommendation 2: Specify Tier 2 Classifier Concretely (Effort: M)
**Rationale**: Findings F-01, F-04, F-13. The Tier 2 classifier is the product's core differentiator and its most underspecified component. The spec must decide between:

| Option | Latency | Dependency | Accuracy | MVP Feasibility |
|--------|---------|------------|----------|-----------------|
| **A. Heuristic NLP** (keyword co-occurrence, TF-IDF title-vs-body mismatch) | <50ms | None | Medium | ✅ Fits 10-day timeline |
| **B. Local small model** (distilBERT fine-tuned on attack corpus) | 100-300ms | ~200MB model binary | High | ⚠️ Needs training data |
| **C. External LLM API** (GPT-4o-mini / Claude Haiku) | 500-2000ms | Network + API key | Highest | ❌ Breaks offline, <500ms, zero-dep goals |

> **[AI] recommends Option A for MVP, with Option B as a v1.1 fast-follow.** Option C should only be offered as an opt-in `--deep-scan` mode, never as the default path.
>
> **[CE] agrees** — Option A is the only one that satisfies the stated non-functional requirements.
>
> **[SA] dissents partially** — If you ship Option A only, be honest in marketing that Tier 2 is "heuristic intent analysis," not "AI-powered semantic classification." Misrepresenting heuristics as AI is a credibility risk for a security product.

---

### Recommendation 3: Threat-Model RudrAI Itself (Effort: M)
**Rationale**: Findings F-02, F-05, F-09, F-10. A security scanning tool that ships without its own threat model is a professional liability. Apply STRIDE to the scanner:

| STRIDE Category | RudrAI Self-Threat | Mitigation |
|---|---|---|
| **Spoofing** | Attacker creates a fake `rudrai` package on PyPI (typosquatting) | Reserve package name now; sign releases |
| **Tampering** | Poisoned `.rudrai.yaml` disables critical rules | Log all exclusions; warn on rule suppressions; support `--strict` mode that ignores config overrides |
| **Repudiation** | CI scan says "clean" but findings were suppressed | Sign SARIF output; emit immutable scan event log |
| **Information Disclosure** | Tier 2 API calls leak source code to third-party LLM | Default to offline; if API mode, redact file contents to structural features only |
| **Denial of Service** | Adversary crafts a 50MB SKILL.md to hang the scanner | File size limits; scanning timeouts per file |
| **Elevation of Privilege** | Custom rule pack with `os.system()` in YAML processing | Rules are **data** (YAML patterns), never executable code; use safe YAML loader; never `eval()` |

---

### Recommendation 4: Resolve the Stack Decision and Bridge the Two Documents (Effort: S)
**Rationale**: Finding F-03. The two documents are architecturally disconnected. The requirements spec envisions a Java/Spring/Oracle platform. The MVP spec describes a Python CLI. Neither references the other's architecture.

**Concrete deliverable**: Write a one-page "Architecture Decision Record" (ADR) that answers:
1. Is the MVP scanner a standalone Python tool that feeds into a future Java platform via SARIF/API?
2. Or is the entire platform being built in Python?
3. If mixed, what is the integration contract? (SARIF file? REST API? gRPC? Message queue?)
4. When does the Java/Spring/Oracle architecture actually enter the picture? (Stage 2? Stage 3?)

> **[CE]**: If the answer is "Java platform with Python CLI scanner," that's a perfectly valid polyglot architecture (like SonarQube: Java server + multi-language scanners). But the integration boundary must be designed now, not discovered later.

---

### Recommendation 5: Add Confidence Scoring and Cross-File Analysis (Effort: M)
**Rationale**: Findings F-12, F-16. Without confidence scoring, the scanner will drown users in false positives (any SSH tutorial mentioning `~/.ssh` becomes a CRITICAL finding) and die on the adoption curve. Without cross-file analysis, split-payload attacks are invisible.

**Concrete deliverables**:
1. **Confidence model**: Every finding gets a `confidence: HIGH | MEDIUM | LOW` field. Single-tier corroboration = MEDIUM. Multi-tier corroboration = HIGH. Contextual override (e.g., file is in a `test/` or `examples/` directory) = LOW. CLI supports `--min-confidence=high`.
2. **Cross-file reference graph**: When a skill/rule file references another file (e.g., `source: ./scripts/setup.sh`), resolve the reference within the workspace and analyze the target. When an MCP config specifies a local command, analyze that command's script.

---

## 4. Open Questions to Resolve Before Next Iteration

> [!IMPORTANT]
> These are blocking questions — each one represents an ambiguity that would cause an architecture review board to send this back for revision.

1. **Stack decision**: Is the platform Java/Spring/Oracle or Python-native? If polyglot, what is the integration contract between the Python scanner and the Java platform? *(Blocks all engineering)*

2. **Tier 2 implementation**: What specifically powers the Semantic Intent Classifier in the MVP? Heuristic NLP? Local model? External API? What is the latency budget for Tier 2 within the <500ms total target? *(Blocks Phase 2 of the 10-day plan)*

3. **Offline vs. connected**: Is the MVP scanner designed to work fully offline (air-gapped enterprise environments)? If yes, Tier 3 registry checks and any API-based Tier 2 classifier are opt-in. If no, what is the failure mode when network is unavailable? *(Blocks CI/CD integration design)*

4. **Rule update model**: How are new detection signatures distributed after initial install? Auto-update (attack surface)? Manual update (stale signatures)? Separate package (version coupling)? *(Blocks go-to-market and enterprise sales)*

5. **False positive management**: What is the target false-positive rate? How do users suppress false positives — inline annotations, config file, or both? Is there a "learn" mode that reduces noise over time? *(Blocks adoption — noisy security tools get uninstalled)*

6. **Scope of "Semantic Intent"**: The Numa case is clean: title says "Style Guide," body says "curl | bash." But what about gray areas — a legitimate DevOps skill that includes `curl` to fetch dependencies? How does the classifier distinguish malicious intent from legitimate automation? *(Blocks Tier 2 design)*

7. **Competitive moat**: The Tier 1 heuristic engine is easily replicated by Semgrep custom rules. What prevents a Semgrep rule pack from covering 80% of RudrAI's MVP value? Is the moat in Tier 2 (semantic analysis), Tier 3 (registry integration), or the purpose-built UX for agent security? *(Strategic, not blocking, but important for investment thesis)*

8. **Windows parity**: The spec is Linux/macOS-centric in its examples and threat patterns. Is Windows a first-class target at MVP? If yes, expand heuristics for Windows persistence mechanisms and credential paths. *(Blocks completeness claim)*

---

## 5. Suggested Reference Frameworks

Map the spec against these standards explicitly. This both strengthens the product's credibility and reveals coverage gaps:

| Framework | Relevance to RudrAI | Suggested Action |
|-----------|---------------------|------------------|
| **OWASP Top 10 for LLM Applications (2025)** | Directly applicable. The spec's 10-threat matrix partially maps but doesn't reference OWASP LLM explicitly. | Create an explicit traceability matrix: each OWASP LLM Top 10 item → RudrAI detection capability (or gap). |
| **OWASP Agentic AI Threats (2025)** | The spec's threat vectors align closely but use custom terminology. | Adopt OWASP Agentic AI nomenclature where possible to ease enterprise security team adoption. |
| **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)** | Provides a structured kill chain for AI attacks. RudrAI's detection tiers can be mapped to ATLAS techniques. | Map each detection rule to ATLAS technique IDs (e.g., AML.T0051 for prompt injection). This enables integration with enterprise threat intelligence platforms. |
| **NIST AI RMF (AI 600-1)** | Governance framework. Relevant for Stage 3 enterprise chatbot customers who need compliance documentation. | Not critical for MVP, but design the finding schema to be mappable to NIST AI RMF risk categories for future compliance reporting. |
| **CWE (Common Weakness Enumeration)** | SARIF output should reference CWE IDs for integration with existing AppSec tooling (e.g., GitHub code scanning, Snyk). | Assign CWE IDs to each rule where applicable (e.g., CWE-94 for code injection, CWE-200 for information exposure, CWE-829 for untrusted functionality inclusion). |
| **SARIF 2.1.0 Specification** | The spec mentions SARIF output but doesn't specify compliance level. | Ensure full SARIF 2.1.0 compliance including `tool`, `invocations`, `results` with `ruleId`, `message`, `locations`, `level`, and `fingerprints` for deduplication across runs. |

---

## Panel Closing Notes

**[SA]**: This is a genuinely important product idea targeting a real gap. The Numa case study is compelling and the market analysis is well-researched. But the spec reads like a product brief, not a security architecture document. Before building, you need: (1) a threat model of RudrAI itself, (2) an integrity model for rules and output, and (3) a clear identity/auth story even for a CLI tool.

**[AI]**: The 3-tier detection hierarchy is the right idea. The critical mistake in the current design is the pipeline routing — letting Tier 1 "clean" files bypass Tier 2. Fix that, resolve the Tier 2 implementation question, and you have a defensible architecture. I'd also urge you to build an evaluation harness (a corpus of known-good and known-malicious agent configs) from day 1. Without it, you can't measure whether your detection actually works.

**[CE]**: I want to see a realistic benchmark before I believe the <1.5s / 1,000-file claim, especially if Tier 2 involves any NLP. The Python stack is fine for the CLI scanner, but the requirements spec's vision of a multi-tenant platform with an audit store and RBAC screams "this will eventually be a Java/Spring service." Decide that now, not after you've built two disconnected systems. Also: the 10-day timeline for Phase 1-3 is aggressive but achievable for a *heuristic-only* MVP. If Tier 2 requires any ML, double it.
