# RudrAI: Unified Security & Vulnerability Auditing Platform for AI Agents
## Initial Requirements Specification & Architecture Blueprint

---

## 1. Executive Summary & Product Vision

### 1.1 Mission
Modern AI systems have rapidly shifted from passive text-completion APIs to **autonomous agents** possessing execution environments, tool-calling privileges, shell access, and multi-tenant data retrieval capabilities. Examples include local developer agents (**Claude Code, Cursor IDE, Codex, Copilot CLI**) and **customer-facing enterprise chatbots / RAG agents**.

Traditional application security (SAST/DAST/EDR) treats natural language files as passive text and model outputs as strings. In agentic systems, **natural language instructions serve as executable code**. 

**RudrAI** is designed to audit, detect, intercept, and mitigate vulnerabilities across:
1. **Internal Developer Agent Workflows** (e.g., poisoned skills, rogue MCP servers, credential theft, unsandboxed shell execution).
2. **Customer-Facing Agentic Chatbots** (e.g., prompt injection, multi-tenant RAG data leakage, unauthorized tool parameter manipulation, transaction spoofing).

---

## 2. Problem Statement & Real-World Attack Case Study

### 2.1 The Numa Incident: Living-Off-The-Agent (LotA) & Skill Poisoning
In a documented attack against Claude Code users, an attacker successfully compromised a local development machine through a multi-stage infection loop:

```
[Phase 1: Delivery]
User requests transcription utility in Claude chat.
Model references a malicious copycat repository/link.
User pastes setup command into terminal.

[Phase 2: Persistence & Camouflage]
Malware writes a poisoned `SKILL.md` into local Claude Code config/skills directory.
The file is camouflaged as a benign "Writing Style Guide".

[Phase 3: Ambient Trigger]
User wipes machine, restores backup including workspace skills.
Developer launches Claude Code for regular work.

[Phase 4: Agent-Driven Exploitation]
Claude Code ingests `SKILL.md` with implicit trust.
Hidden prompt instructions order the agent to:
- Re-download remote payload silently via shell tools.
- Read and exfiltrate credentials (`~/.ssh`, `~/.aws`, `.env`).
```

### 2.2 Why Existing Security Tools Failed
- **EDR / Anti-Virus**: Does not flag markdown files (`SKILL.md`, `.cursorrules`, `CLAUDE.md`, `mcp.json`) as executables.
- **Git / Secret Scanners**: Misses natural language instructions formatted as formatting guidelines or prompt directives.
- **Agent Runtimes**: Execute instructions with **ambient authority**—inheriting full privileges of the developer's user account and terminal session.

---

## 3. Market Landscape & Competitive Differentiation
*(Derived from market analysis of HiddenLayer, WitnessAI, Zenity, Credo AI, and Prophet Security)*

| Solution Type | Incumbent Examples | Valuation / Funding | Primary Focus | The Critical Blindspot |
| :--- | :--- | :--- | :--- | :--- |
| **MLSecOps / Model Scanning** | HiddenLayer | ~$383M | Scans `.pkl`, `.onnx` models, model weight tampering, model-level DDoS | Misses agent context files, MCP configurations, and IDE tool execution |
| **Network / Proxy AI Gateways** | WitnessAI | $58M (Jan 2026) | Gateway prompt-injection filtering, shadow AI discovery, data leakage | Cannot inspect local IDE contexts, filesystem hooks, or local CLI agents |
| **Enterprise Copilot Governance** | Zenity | $125M Series C | Enterprise SaaS copilots (M365, Salesforce), excessive SaaS permissions | Enterprise CISO/SaaS-focused; not developer-native; misses local agent tool loops |
| **AI Governance & Compliance** | Credo AI | ~$101M | Risk registers, EU AI Act compliance, audit documentation | Governance/documentation only; no technical interception or vulnerability scanning |

### RudrAI's Strategic Wedge:
No existing player provides a developer-native, modular scanner that audits **Agent Configs, Skills, MCP Servers, and Agentic Tool-Calling Workflows** like a "Snyk / Semgrep for AI Agents."

---

## 4. Target Segment 1: Internal Dev Teams (Developer Agents)
*Target Environments: Claude Code, Cursor IDE, Codex, Copilot CLI, Local Agent Workflows*

### 4.1 Primary Threat Vectors
1. **Agent Skill & Rule Poisoning**:
   - Files: `SKILL.md`, `.cursorrules`, `CLAUDE.md`, `.agentrules`, prompt instructions.
   - Attack: Embedded indirect prompts commanding the LLM to access credentials, modify files out-of-scope, or fetch remote scripts.
2. **Model Context Protocol (MCP) & Plugin Supply Chain**:
   - Files: `mcp.json`, custom MCP server manifests.
   - Attack: Malicious MCP servers declaring broad tool privileges (e.g., wildcard filesystem permissions, unrestricted curl/network access, arbitrary command execution).
3. **AI Package Hallucination ("Slopsploitation")**:
   - Attack: Developers ask agents to solve problems; agents generate code importing hallucinated packages. Attackers register these packages on npm/PyPI to trigger remote code execution during `npm install` or `pip install`.
4. **Credential & Secrets Ingestion**:
   - Attack: Agents scanning local projects inadvertently read `.env`, SSH keys, or cloud tokens into context, transmitting them in cleartext prompts to model API endpoints.
5. **Unsandboxed Shell Tool Execution**:
   - Attack: Agents running destructive commands (`rm -rf`, force-pushing Git branches, overriding CI/CD scripts) without human boundary checks.

### 4.2 Required Technical Capabilities
- **Agent SAST (Static Analysis)**: Semantic and heuristic scanner for agent configuration files (`SKILL.md`, `.cursorrules`, `mcp.json`).
- **MCP Permission Analyzer**: Evaluates MCP server definitions against the Principle of Least Privilege.
- **Package Hallucination Verifier**: Intercepts generated dependencies and verifies them against live PyPI/npm registries before installation.
- **Local Pre-Execution Hook / Shim**: A lightweight terminal interceptor for agent CLI tools that validates bash/shell calls before execution.

---

## 5. Target Segment 2: Customer-Facing Chatbots
*Target Environments: Support Bots, Transactional Agents, Autonomous Workflow Bots, Enterprise RAG*

### 5.1 Primary Threat Vectors
1. **Direct & Indirect Prompt Injection**:
   - Attack: End-users craft adversarial inputs or upload documents with hidden text that override system guardrails, extract system prompts, or induce toxic outputs.
2. **Multi-Tenant RAG Data Contamination (IDOR in Vector Stores)**:
   - Attack: Flawed retrieval filters allow Customer A to pull embedding chunks containing confidential data, PII, or financial records of Customer B.
3. **Tool Parameter Manipulation & Unauthorized State Changes**:
   - Attack: Tricking the agent into issuing unauthorized API calls (e.g., executing refunds beyond policy limits, modifying database records, sending unauthorized emails).
4. **Prompt & Context Denial of Service (DoS)**:
   - Attack: Recursive prompting, huge context stuffing, or token-exhaustion attacks driving up inference bills and degrading latency.

### 5.2 Required Technical Capabilities
- **Inline AI Gateway / Reverse Proxy**: Sits between application backend and LLM providers (OpenAI, Anthropic, Bedrock, Vertex).
- **RAG Pre-Context Sanitizer**: Validates tenant IDs and filters prompt injection artifacts out of vector search results *before* passing them to the model context.
- **Deterministic Tool Authorization Engine**: Validates parameters of LLM tool calls against strict schemas, user entitlements, and role-based policies before hitting backend APIs.
- **PII / Sensitive Data Redaction**: Real-time bidirectional masking of sensitive customer identifiers.

---

## 6. Functional Architecture & Taxonomy Matrix
*(Based on the 39 Core Build Elements)*

```
+---------------------------------------------------------------------------------------+
|                                     RUDRAI PLATFORM                                   |
+---------------------------------------------------------------------------------------+
|  Tier 1: Core Foundation & Telemetry                                                  |
|  - Common AI Event Schema (Normalized Prompts, Tool-Calls, Model Responses)          |
|  - Threat Model & Risk Taxonomy (Standardized risk categories)                        |
|  - Immutable Event & Audit Store (Append-only tamper-evident logs)                    |
|  - Multi-Tenant Data Isolation & RBAC Engine                                          |
+---------------------------------------------------------------------------------------+
|  Tier 2: Static & Supply Chain Security (Shift-Left for Dev Teams)                    |
|  - Skill & Prompt Rule Scanner (Detects malicious instructions in SKILL.md, rules)    |
|  - MCP Server & Tool Manifest Auditor (Permissions, network endpoints, tool schemas)  |
|  - Package Hallucination Verification Service (PyPI / npm registry validation)        |
|  - Git & CI/CD Security Gate (Pre-commit hooks, PR scanners)                          |
+---------------------------------------------------------------------------------------+
|  Tier 3: Runtime Agent Interception (Local Dev Machine Protection)                    |
|  - Claude Code / Cursor / Codex Execution Shim (CLI wrapper / IDE Hook)               |
|  - Local Shell Command Policy Interceptor (Blocks destructive / exfiltration commands)|
|  - Local Secret / Path Guard (Blocks agent access to ~/.ssh, ~/.aws, .env)            |
+---------------------------------------------------------------------------------------+
|  Tier 4: Chatbot Runtime Gateway & RAG Firewall                                       |
|  - High-Throughput Model Proxy (Streaming-compatible prompt/output inspection)        |
|  - Prompt-Injection & Jailbreak Classifier                                           |
|  - RAG Retrieval Inspector & Tenant Boundary Validator                               |
|  - Deterministic Tool-Call Policy Engine (Parameter constraint & authorization checks)|
+---------------------------------------------------------------------------------------+
```

---

## 7. Requirements Maturity & Staged Evolution

To avoid building an unwieldy, high-overhead system, requirements are organized into three evolutionary stages:

```
[Stage 1: Agent SAST & Config Auditor]
                │
                ▼
[Stage 2: Developer Agent Local Shield & CLI Shim]
                │
                ▼
[Stage 3: Chatbot Gateway & RAG/Tool Firewall]
```

### Stage 1: The Scanner Wedge (Fastest Time-to-Value)
- **Objective**: Audit repositories, IDE configurations, and agent setups for vulnerabilities without requiring complex runtime infrastructure.
- **Capabilities**:
  - CLI scanner: `rudrai scan .`
  - Scans `SKILL.md`, `.cursorrules`, `CLAUDE.md`, `.agentrules`, and `mcp.json`.
  - Flags high-risk patterns: shell invocation directives, suspicious outbound URLs, credential-reading instructions, overly permissive MCP tools.
  - CI/CD Action / Pre-commit hook integration.

### Stage 2: Local Developer Agent Shield
- **Objective**: Prevent real-time exploitation on developer workstations during agent execution.
- **Capabilities**:
  - Process hook / CLI proxy for Claude Code, Cursor terminal sessions.
  - Policy enforcement: Restrict shell execution to approved command allowlists.
  - Sandboxed access to sensitive directories (`~/.ssh`, `~/.aws`, `.env`).
  - Interactive prompt warning developers before dangerous actions take place.

### Stage 3: Chatbot Runtime Gateway & Tool Firewall
- **Objective**: Protect customer-facing agents and RAG applications in production.
- **Capabilities**:
  - API Gateway / SDK middleware.
  - Prompt injection detection & RAG context sanitization.
  - Tool authorization engine: parameter range validation, tenant verification.
  - SIEM / Webhook alerting (Splunk, Datadog, Slack).

---

## 8. Path to Defining the Single MVP

### Key Trade-Off Analysis:

| Evaluation Dimension | Option A: Dev Agent Scanner (Stage 1) | Option B: Chatbot Runtime Gateway (Stage 3) |
| :--- | :--- | :--- |
| **Implementation Complexity** | **Low-Medium** (CLI / rules engine / AST parser) | **High** (High-throughput proxy, low latency, streaming support) |
| **Adoption Friction** | **Zero Friction** (Runs in seconds like ESLint/Semgrep) | **High Friction** (Requires modifying production network traffic) |
| **Market Urgency** | **Extreme** (Exploding use of Cursor, Claude Code; zero tooling) | **High** (Well-recognized, but crowded with gateway competitors) |
| **Direct Relevance to Incident** | **100% Match** (Directly prevents the Numa `SKILL.md` exploit) | **Partial Match** (Targets web chatbots, not developer tools) |

### Recommended MVP Decision:
Build **RudrAI Core Scanner (Agent SAST & MCP Auditor)** as the foundational MVP. 
- It directly addresses the poisoned skill vector that attacked Claude Code users.
- It delivers instant value to internal developer teams with zero runtime latency impact.
- It creates the distribution engine to later upsell the runtime agent shield and chatbot gateway.
