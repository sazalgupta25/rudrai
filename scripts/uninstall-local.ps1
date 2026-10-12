<#
.SYNOPSIS
Removes RudrAI's local pipx installation from this checkout.

.DESCRIPTION
Deletes only the ignored .rudrai-pipx folder created by setup-local.ps1. It
does not delete the RudrAI source checkout, Python, pipx installed for the
current user, or saved reports. Pass -UninstallPipPackage to remove a package
installed with `python -m pip` in the currently selected Python environment.
Pass -RemoveScanReports to also delete the ignored rudrai_scans folder in this
checkout.
#>
[CmdletBinding()]
param(
    [switch]$RemoveScanReports,
    [switch]$UninstallPipPackage
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rudraiPipxRoot = Join-Path $repoRoot '.rudrai-pipx'
$scanReportsRoot = Join-Path $repoRoot 'rudrai_scans'

function Remove-RudrAIPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "$Description was not present."
        return
    }

    Write-Host "Removing $Description..."
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Remove-RudrAIPipPackage {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw 'Python was not found, so the pip-installed RudrAI package could not be removed.'
    }

    & $pythonCommand.Source -m pip show rudrai *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'RudrAI was not installed in the Python environment selected by python.'
        return
    }

    Write-Host 'Removing RudrAI from the Python environment selected by python...'
    & $pythonCommand.Source -m pip uninstall --yes rudrai
    if ($LASTEXITCODE -ne 0) {
        throw "pip could not uninstall RudrAI (exit code $LASTEXITCODE)."
    }
}

try {
    Write-Host 'RudrAI local uninstall' -ForegroundColor Cyan
    Write-Host "Repository: $repoRoot"

    Remove-RudrAIPath -Path $rudraiPipxRoot -Description 'the local RudrAI installation'

    if ($UninstallPipPackage) {
        Remove-RudrAIPipPackage
    }

    if ($RemoveScanReports) {
        Remove-RudrAIPath -Path $scanReportsRoot -Description 'saved RudrAI scan reports'
    }
    else {
        Write-Host 'Saved scan reports were kept.'
    }

    Write-Host ''
    Write-Host 'RudrAI is no longer installed from this checkout.' -ForegroundColor Green
    Write-Host 'The source files and Python/pipx remain available.'
    Write-Host 'Run Setup-RudrAI.cmd to install it again.'
}
catch {
    Write-Error "RudrAI uninstall failed: $($_.Exception.Message)"
    exit 1
}
