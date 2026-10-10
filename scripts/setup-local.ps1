<#
.SYNOPSIS
Installs or refreshes RudrAI from this checkout for the current Windows user.

.DESCRIPTION
Uses pipx so RudrAI is isolated from other Python applications. No administrator
rights are required. Pass -RunValidation to run the local test suite and the
fixed benchmark after installation.
#>
[CmdletBinding()]
param(
    [switch]$RunValidation
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# Keep RudrAI's pipx state inside this checkout, separate from broken or managed
# user-profile locations. These values apply only to this setup process. The
# repository's rudrai.cmd launcher and scan runner call the resulting executable
# directly, so no user PATH or registry change is required.
$rudraiPipxRoot = Join-Path $repoRoot '.rudrai-pipx'
$env:PIPX_HOME = Join-Path $rudraiPipxRoot 'home'
$env:PIPX_BIN_DIR = Join-Path $rudraiPipxRoot 'bin'
$env:LOCALAPPDATA = Join-Path $rudraiPipxRoot 'localappdata'
New-Item -ItemType Directory -Force -Path $env:PIPX_HOME, $env:PIPX_BIN_DIR, $env:LOCALAPPDATA | Out-Null

function Invoke-Python {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & $script:pythonExe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed (exit code $LASTEXITCODE): $($Arguments -join ' ')"
    }
}

function Get-PythonExecutable {
    $command = Get-Command python -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Python 3.10 or newer is required. Install it from https://www.python.org/downloads/windows/ and run this setup again."
    }
    return $command.Source
}

try {
    Write-Host "RudrAI local setup" -ForegroundColor Cyan
    Write-Host "Repository: $repoRoot"
    Write-Host "RudrAI command directory: $env:PIPX_BIN_DIR"

    $pythonExe = Get-PythonExecutable
    $pythonVersion = (& $pythonExe -c "import sys; print('.'.join(map(str, sys.version_info[:3])))").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to determine the installed Python version."
    }
    if ([version]$pythonVersion -lt [version]'3.10') {
        throw "Python 3.10 or newer is required; found Python $pythonVersion."
    }
    Write-Host "Using Python $pythonVersion"

    $pipxInstalled = (& $pythonExe -c "import importlib.util; print(importlib.util.find_spec('pipx') is not None)").Trim() -eq 'True'
    if (-not $pipxInstalled) {
        Write-Host "Installing pipx for the current user..."
        Invoke-Python -Arguments @('-m', 'pip', 'install', '--user', 'pipx')
    }

    Write-Host "Installing RudrAI from this checkout..."
    Invoke-Python -Arguments @('-m', 'pipx', 'install', '--force', '--backend', 'pip', $repoRoot)

    Write-Host "Validating the installed package..."
    Invoke-Python -Arguments @('-m', 'pipx', 'runpip', 'rudrai', 'show', 'rudrai')
    $rudraiExe = Join-Path $env:PIPX_BIN_DIR 'rudrai.exe'
    if (-not (Test-Path -LiteralPath $rudraiExe)) {
        throw "RudrAI was installed but its local launcher was not created: $rudraiExe"
    }
    & $rudraiExe --version
    if ($LASTEXITCODE -ne 0) {
        throw "The installed RudrAI launcher failed its version check."
    }

    if ($RunValidation) {
        Write-Host "Running tests..."
        Push-Location $repoRoot
        try {
            Invoke-Python -Arguments @('-m', 'unittest', 'discover', '-s', 'tests', '-v')
            Write-Host "Running the 1,000-file benchmark..."
            Invoke-Python -Arguments @('scripts/benchmark.py')
        }
        finally {
            Pop-Location
        }
    }

    Write-Host "" 
    Write-Host "RudrAI is installed in this checkout." -ForegroundColor Green
    Write-Host "Run: .\rudrai.cmd --version"
    Write-Host "Example scan: .\rudrai.cmd scan C:\path\to\your-project"
    Write-Host "For scoped reports: .\scripts\run-rudrai-scan.ps1 C:\path\to\your-project"
}
catch {
    Write-Error "RudrAI setup failed: $($_.Exception.Message)"
    exit 1
}
