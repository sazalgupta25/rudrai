# Configuration

RudrAI reads one optional `.rudrai.yaml` file from the scan root. The parser
accepts only the documented data schema and never evaluates YAML tags or code.

```yaml
max_file_size: 1048576
exclude:
  - fixtures/generated/**
suppressions:
  - rule_id: RAI-DEP-003
    path: requirements.txt
    reason: Reviewed floating dependency for an internal package
    owner: appsec
    expires: 2026-12-31
```

Required suppression fields are `rule_id`, `path`, and `reason`. `owner` and an
ISO `expires` date are optional. Expired suppressions no longer apply.

Suppressed findings remain in terminal, JSON, SARIF, and event output. Run with
`--strict` to ignore every suppression. Local custom rules and inline ignore
comments are not supported in MVP-1.

