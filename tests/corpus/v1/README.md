# RudrAI evaluation corpus v1

This corpus is a versioned regression gate for deterministic offline detection.
Each case is labeled in `expectations.json` with the complete expected finding
set, including rule, severity, confidence, file, and line. Benign cases have a
zero false-positive budget. Cases marked `critical` must retain at least one
critical finding.

The corpus is intentionally small in v1. It covers negated and quoted commands,
signal separation, remote execution, camouflaged credential access, Windows
persistence, payload obfuscation, MCP overprivilege and safe configuration,
direct URL and pinned dependencies, and split payloads.
It is not a precision/recall claim beyond these labeled fixtures.
