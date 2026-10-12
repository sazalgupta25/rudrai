# RudrAI

RudrAI is an offline-first static security scanner for AI-agent instruction files,
MCP/tool configurations, and dependency manifests.

## Install for development

```bash
python -m pip install -e .
```

For an isolated user installation after publishing:

```bash
pipx install rudrai
```

For a Windows local install from this checkout, double-click
`Setup-RudrAI.cmd`, or run:

```powershell
.\scripts\setup-local.ps1
```

Use `-RunValidation` to run the local tests and benchmark after installation.
To remove that local installation later, double-click `Uninstall-RudrAI.cmd` or
run `./scripts/uninstall-local.ps1` from PowerShell. It keeps your scan reports
unless you explicitly choose their removal. For a `pip` installation, run
`python -m pip uninstall rudrai`.

## Scan

```bash
rudrai scan .
rudrai scan . --format json --output rudrai-results.json
rudrai scan . --format sarif --output rudrai-results.sarif
rudrai scan . --events-file rudrai-events.jsonl
```

The default scan performs no network requests. Findings at `HIGH` or `CRITICAL`
severity produce exit code `1`; usage errors produce `2`, and operational failures
produce `3`.

## Documentation

- [Engineering execution specification](docs/RUDRAI_ENGINEERING_EXECUTION_SPEC.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Configuration](docs/CONFIGURATION.md)
- [Deployment](docs/DEPLOYMENT.md)
- [TestPyPI and PyPI publishing](docs/DEPLOYMENT.md#8-publish-a-release-to-testpypi)
- [Requirements and architecture documents](docs/README.md)

