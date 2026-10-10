# Deployment

RudrAI MVP-1 is distributed as a Python package and the `rudrai` console
command. It does not require a backend service, database, container runtime, or
network connection while scanning.

## 1. Prerequisites

RudrAI requires Python 3.10 or newer. Verify Python and pip before continuing:

```text
python --version
python -m pip --version
```

On systems where Python 3 is exposed as `python3`, use `python3` in the setup
commands instead.

The recommended user installation uses `pipx`, which keeps RudrAI isolated from
other Python applications.

### Windows PowerShell

```powershell
python -m pip install --user pipx
python -m pipx ensurepath
```

Close and reopen PowerShell after `ensurepath` so the updated `PATH` is loaded.

### macOS

```bash
brew install pipx
pipx ensurepath
```

### Ubuntu or Debian Linux

```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
```

Restart the shell after installing `pipx`, then verify it:

```text
pipx --version
```

## 2. Get the source checkout

Clone or copy the repository, then change to its root—the directory containing
`pyproject.toml`:

```text
cd path/to/rudrai
```

On this workstation, the canonical checkout is:

```powershell
Set-Location C:\sazal\rudrai
```

## 3. Recommended local deployment with pipx

### One-click Windows setup

From the repository root, double-click `Setup-RudrAI.cmd`. It starts
`scripts/setup-local.ps1`, which checks Python, installs `pipx` for the current
user if needed, and installs or refreshes RudrAI from this checkout. It keeps
RudrAI's `pipx` environment in the ignored
`.rudrai-pipx` folder within this checkout, avoiding conflicts with other `pipx`
installations or restricted profile folders. It does not require administrator
privileges.

The launcher uses an execution-policy bypass only for its own PowerShell process;
it does not change the computer's saved execution policy or PATH. Review the
PowerShell script before running it if the checkout is not trusted. After setup,
run `rudrai.cmd --version` from the repository root; the scoped scan runner uses
the same local installation automatically.

For an install plus test and benchmark validation, run:

```powershell
.\scripts\setup-local.ps1 -RunValidation
```

Install directly from the current checkout:

```text
pipx install --backend pip .
rudrai --version
```

The explicit `pip` backend makes local-path install and lifecycle behavior
consistent on machines where `pipx` might otherwise auto-select `uv`.

Run a workspace scan:

```text
rudrai scan .
```

The default scan is offline. An unsuppressed `HIGH` or `CRITICAL` finding
returns exit code `1`.

## 4. Development installation in a virtual environment

Use this path when modifying RudrAI itself.

### Windows PowerShell

```powershell
Set-Location C:\sazal\rudrai
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
rudrai --version
```

### macOS or Linux

```bash
cd path/to/rudrai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
rudrai --version
```

Run `deactivate` when finished.

Source installation may download the declared build tooling. For an air-gapped
machine, build and transfer a wheel as described below instead.

## 5. Verify the deployment

Run the automated test suite:

```text
python -m unittest discover -s tests -v
```

Run the fixed 1,000-file benchmark:

```text
python scripts/benchmark.py
```

The benchmark passes when it scans all 1,000 candidate files in under 1.5
seconds. Results vary by storage, antivirus, operating system, and available CPU.

Verify both scanner exit paths:

```text
rudrai scan tests/fixtures/benign --quiet
rudrai scan tests/fixtures/malicious --quiet
```

The benign fixture should return `0`. The malicious fixture should report
findings and return `1`; that nonzero result is expected.

## 6. Produce and install release artifacts

Install the packaging frontend and build a source distribution plus wheel:

```text
python -m pip install build
python -m build
```

Artifacts are written under `dist/`. Test the wheel on every supported Python
and operating-system target before promotion.

For an offline or controlled environment:

1. Build the wheel on a connected, trusted build machine.
2. Record and verify its SHA-256 checksum.
3. Download runtime dependency wheels for the target Python and operating system
   into a `wheelhouse/` on the connected machine. Dependencies are `pathspec` and,
   on Python 3.10, `tomli`; transfer their checksums and wheels with RudrAI.
4. Install using only the transferred wheelhouse:

```text
pipx install --backend pip --pip-args="--no-index --find-links=./wheelhouse" ./dist/rudrai-0.1.0-py3-none-any.whl
```

Adjust the filename for the release version being installed. Runtime scanning
does not require network access.

## 7. Reinstall, upgrade, and uninstall

For a `pipx` installation made from the local checkout:

```text
pipx reinstall --backend pip rudrai
pipx upgrade --backend pip rudrai
```

An upgrade of a local-path installation rebuilds from its recorded local source.
To replace it explicitly from the current checkout, run:

```text
pipx install --force --backend pip .
```

Remove the installation with:

```text
pipx uninstall rudrai
```

For an activated development virtual environment, refresh the editable install
with `python -m pip install --upgrade -e .`.

## 8. Published-package status

The `rudrai` distribution is not currently published on PyPI. Until publication,
this command will not install the project:

```text
pipx install rudrai
```

Use `pipx install --backend pip .` from the repository root or install a locally
built wheel. After an official release is published, the expected public install
command will be `pipx install rudrai`.

## 9. CI gate

Run RudrAI as a CI security gate and retain SARIF as an artifact:

```text
rudrai scan . --format sarif --output rudrai-results.sarif --fail-on high
```

Exit codes are stable:

- `0`: scan completed without an unsuppressed finding at the selected threshold.
- `1`: scan completed and found an unsuppressed finding at the threshold.
- `2`: invalid CLI usage or configuration.
- `3`: operational scan/output failure or incomplete coverage (including unreadable,
  oversized, malformed or blocked referenced files), even with `--fail-on none`.

Intentional exclusions do not make a scan partial. `--strict` disables finding
suppressions only; it retains path exclusions. JSON/SARIF record completeness.
Treat incomplete coverage as a failed gate, not a clean result.

File reports are accompanied by `<report>.sha256`. Verify the exact bytes with:

```text
rudrai verify rudrai-results.sarif
```

Verification returns `0` for matching bytes, `1` for mismatch and `3` for read
failure. This is a checksum, not a signature or proof of trusted provenance.

The root `action.yml` provides a composite GitHub Action for repositories that
consume RudrAI from a checked-out release. `.github/workflows/ci.yml` runs the
test suite on Python 3.10 through 3.13 across Windows, macOS, and Linux and builds
the distribution. Matrix configuration is not evidence of passing remote jobs;
review all job results before a public release.

## 10. Scoped Windows scan runner

`scripts/run-rudrai-scan.ps1` saves a timestamped report and JSONL event file in
the ignored `rudrai_scans` folder in this checkout by default. It uses the `Project` profile by default,
which excludes generated/vendor folders, test fixtures, documentation and example
directories to reduce noise. This is an explicit scope choice, not a clean bill
of health for those excluded paths.

For SARIF or JSON scans, it also saves a `.summary.txt` file that presents every
finding with its location, evidence, problem statement and remediation. SARIF and
JSON remain the machine-readable artifacts; read the summary first during manual
triage.

Run it against a project:

```powershell
.\scripts\run-rudrai-scan.ps1 C:\path\to\project
```

Use the `Home` profile for a personal-machine scan; it additionally excludes
Codex, Claude, IDE, cache and application-data directories:

```powershell
.\scripts\run-rudrai-scan.ps1 $HOME -Profile Home
```

To deliberately scan documentation or examples, opt in:

```powershell
.\scripts\run-rudrai-scan.ps1 C:\path\to\project -IncludeDocumentation -IncludeExamples
```

Select JSON instead of SARIF, choose destinations, or enable strict mode:

```powershell
.\scripts\run-rudrai-scan.ps1 C:\path\to\project -Format json -OutputPath C:\reports\scan.json -EventsFile C:\reports\events.jsonl -Strict
```

The runner keeps an interactive PowerShell window open by default and sets
`$LASTEXITCODE` to RudrAI's result. Add `-ExitWithCode` when the script is being
run non-interactively and the caller should receive the scanner's exit code.

## 11. Release boundary

Registry verification is deliberately reserved. Passing `--check-registries`
returns exit code `2` instead of silently making a network request. Connected
mode requires a separate threat model, endpoint policy, timeout/cache behavior,
and test suite before release.

