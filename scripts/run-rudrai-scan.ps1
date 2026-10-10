<#
.SYNOPSIS
Runs a scoped RudrAI scan with timestamped report and event files.

.DESCRIPTION
The project profile skips generated, vendor, test-fixture, documentation and
example directories by default. The home profile adds local tool/cache folders
that otherwise dominate personal-machine scans. Use -IncludeDocumentation or
-IncludeExamples when those directories are in scope for a specific review.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$TargetPath = (Get-Location).Path,

    [ValidateSet('sarif', 'json', 'table')]
    [string]$Format = 'sarif',

    [string]$OutputPath,

    [string]$EventsFile,

    [string]$SummaryPath,

    [ValidateSet('Project', 'Home')]
    [string]$Profile = 'Project',

    [ValidateSet('low', 'medium', 'high', 'critical', 'none')]
    [string]$FailOn = 'high',

    [switch]$Strict,
    [switch]$IncludeDocumentation,
    [switch]$IncludeExamples,
    [switch]$ExitWithCode
)

$ErrorActionPreference = 'Stop'

$projectExclusions = @(
    '.git/**', 'node_modules/**', '.venv/**', 'venv/**',
    'dist/**', 'build/**', 'coverage/**', '__pycache__/**',
    'tests/fixtures/**', 'test/fixtures/**'
)
$documentationExclusions = @('docs/**', 'documentation/**')
$exampleExclusions = @('examples/**', 'example/**', 'samples/**', 'sample/**')
$homeExclusions = @(
    '.codex/**', '.agents/**', '.antigravity/**', '.antigravity-ide/**',
    '.claude/**', '.cache/**', '.vscode/**', 'AppData/**'
)

function Write-HumanSummary {
    param(
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [Parameter(Mandatory = $true)][string]$ReportFormat,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $payload = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('RudrAI scan summary')
    $lines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("Machine-readable report: $ReportPath")
    $lines.Add('')

    if ($ReportFormat -eq 'sarif') {
        $run = $payload.runs[0]
        $rules = @{}
        foreach ($rule in @($run.tool.driver.rules)) { $rules[$rule.id] = $rule }
        $findings = @($run.results)
        if ($findings.Count -eq 0) {
            $lines.Add('No findings were recorded in this scan.')
        }
        foreach ($finding in $findings) {
            $rule = $rules[$finding.ruleId]
            $location = $finding.locations[0].physicalLocation
            $lines.Add("[$($finding.properties.severity) / $($finding.properties.confidence)] $($finding.ruleId)")
            $lines.Add("Location: $($location.artifactLocation.uri):$($location.region.startLine)")
            $lines.Add("Problem: $($finding.message.text)")
            $lines.Add("Evidence: $($finding.properties.evidence)")
            $lines.Add("Remediation: $($rule.help.text)")
            $lines.Add('')
        }
    }
    else {
        $findings = @($payload.findings)
        if ($findings.Count -eq 0) {
            $lines.Add('No findings were recorded in this scan.')
        }
        foreach ($finding in $findings) {
            $lines.Add("[$($finding.severity) / $($finding.confidence)] $($finding.rule_id)")
            $lines.Add("Location: $($finding.file):$($finding.start_line)")
            $lines.Add("Problem: $($finding.message)")
            $lines.Add("Evidence: $($finding.evidence)")
            $lines.Add("Remediation: $($finding.remediation)")
            $lines.Add('')
        }
    }
    Set-Content -LiteralPath $Destination -Value $lines -Encoding utf8
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $localRudrai = Join-Path $repoRoot '.rudrai-pipx\bin\rudrai.exe'
    $rudrai = Get-Command rudrai -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $localRudrai) {
        $rudraiExe = $localRudrai
    }
    elseif ($rudrai) {
        $rudraiExe = $rudrai.Source
    }
    else {
        throw "RudrAI is not installed. Run Setup-RudrAI.cmd first."
    }

    $target = (Resolve-Path -LiteralPath $TargetPath -ErrorAction Stop).Path
    $reportDirectory = Join-Path $repoRoot 'rudrai_scans'
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeTargetName = (Split-Path -Leaf $target) -replace '[^A-Za-z0-9._-]', '_'
    if (-not $safeTargetName) { $safeTargetName = 'scan' }

    if (-not $OutputPath) {
        $OutputPath = Join-Path $reportDirectory "rudrai-$safeTargetName-$timestamp.$Format"
    }
    if (-not $EventsFile) {
        $EventsFile = Join-Path $reportDirectory "rudrai-$safeTargetName-$timestamp.events.jsonl"
    }
    if (-not $SummaryPath -and $Format -ne 'table') {
        $SummaryPath = Join-Path $reportDirectory "rudrai-$safeTargetName-$timestamp.summary.txt"
    }

    foreach ($path in @($OutputPath, $EventsFile, $SummaryPath) | Where-Object { $_ }) {
        $parent = Split-Path -Parent $path
        if ($parent) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
    }

    $exclusions = [System.Collections.Generic.List[string]]::new()
    $projectExclusions | ForEach-Object { $exclusions.Add($_) }
    if (-not $IncludeDocumentation) { $documentationExclusions | ForEach-Object { $exclusions.Add($_) } }
    if (-not $IncludeExamples) { $exampleExclusions | ForEach-Object { $exclusions.Add($_) } }
    if ($Profile -eq 'Home') { $homeExclusions | ForEach-Object { $exclusions.Add($_) } }

    $arguments = @(
        'scan', $target,
        '--format', $Format,
        '--output', $OutputPath,
        '--events-file', $EventsFile,
        '--fail-on', $FailOn
    )
    if ($Strict) { $arguments += '--strict' }
    foreach ($exclusion in $exclusions) {
        $arguments += '--exclude'
        $arguments += $exclusion
    }

    Write-Host "RudrAI scan profile: $Profile" -ForegroundColor Cyan
    Write-Host "Target: $target"
    Write-Host "Report: $OutputPath"
    Write-Host "Events: $EventsFile"
    if ($SummaryPath) { Write-Host "Readable summary: $SummaryPath" }
    Write-Host "Excluded by scope: $($exclusions -join ', ')"
    Write-Host "Use -IncludeDocumentation or -IncludeExamples to add those paths to this scan."

    & $rudraiExe @arguments
    $scanExit = $LASTEXITCODE

    if ($SummaryPath) {
        Write-HumanSummary -ReportPath $OutputPath -ReportFormat $Format -Destination $SummaryPath
    }

    if ($scanExit -eq 0) {
        Write-Host "Scan completed without findings at the $FailOn threshold." -ForegroundColor Green
    }
    elseif ($scanExit -eq 1) {
        Write-Host "Scan completed with findings at the $FailOn threshold. Review the saved report." -ForegroundColor Yellow
    }
    else {
        Write-Host "Scan did not complete cleanly (exit code $scanExit). Review the saved report and terminal output." -ForegroundColor Red
    }
    if ($ExitWithCode) { exit $scanExit }
    $global:LASTEXITCODE = $scanExit
    return
}
catch {
    Write-Error "RudrAI scan runner failed: $($_.Exception.Message)"
    if ($ExitWithCode) { exit 3 }
    $global:LASTEXITCODE = 3
    return
}
