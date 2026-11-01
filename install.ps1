<#
.SYNOPSIS
    SWA AI - PowerShell Installer for Windows (10/11 & Windows Server)
.DESCRIPTION
    Automates prerequisite detection, virtual environment creation,
    dependency installation, and editable CLI registration.
#>

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SWA AI - Enterprise Installation & Setup (PowerShell)" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Detect Python interpreter (3.10+)
$pyCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py -3"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pyCmd = "python3"
}

if (-not $pyCmd) {
    Write-Host "[-] Python 3 was not found in your Windows PATH!" -ForegroundColor Red
    Write-Host "[!] Please install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "[!] IMPORTANT: Ensure you check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] System Python detected: " -NoNewline -ForegroundColor Green
& $pyCmd --version

# Setup virtual environment
$venvPath = Join-Path $PSScriptRoot "venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[+] Creating virtual environment in .\venv ..." -ForegroundColor Cyan
    & $pyCmd -m venv venv
    if (-not (Test-Path $venvPython)) {
        Write-Host "[!] Warning: Virtual environment creation failed. Using system Python." -ForegroundColor Yellow
        $runPy = $pyCmd
    } else {
        $runPy = $venvPython
    }
} else {
    Write-Host "[+] Existing virtual environment detected." -ForegroundColor Green
    $runPy = $venvPython
}

# Provision default .env if missing
$envFile = Join-Path $PSScriptRoot ".env"
$envExample = Join-Path $PSScriptRoot ".env.example"
if ((-not (Test-Path $envFile)) -and (Test-Path $envExample)) {
    Write-Host "[+] Creating .env from .env.example ..." -ForegroundColor Cyan
    Copy-Item $envExample $envFile
}

# Upgrade pip and install requirements
Write-Host "[+] Upgrading pip in environment ..." -ForegroundColor Cyan
& $runPy -m pip install --upgrade pip

Write-Host "[+] Installing dependencies from requirements.txt ..." -ForegroundColor Cyan
& $runPy -m pip install -r requirements.txt

# Register swa CLI
Write-Host "[+] Registering swa CLI console entry point ..." -ForegroundColor Cyan
& $runPy -m pip install -e .

Write-Host ""
Write-Host "===================================================" -ForegroundColor Green
Write-Host " [✓] SWA AI successfully installed and configured!" -ForegroundColor Green
Write-Host " Launch anytime via: .\run.ps1 or run.bat" -ForegroundColor Cyan
Write-Host " Stop anytime via:   .\stop.ps1 or stop.bat" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Green
