# SWA AI - PowerShell Runner
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SWA AI - Security Operations Center and Cyber Hub" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Detect Python (prefer local virtual environment if present)
$pyCmd = $null
if (Test-Path "$PSScriptRoot\venv\Scripts\python.exe") {
    $pyCmd = "$PSScriptRoot\venv\Scripts\python.exe"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pyCmd = "python3"
}

if (-not $pyCmd) {
    Write-Host "[-] Python 3 was not found in your Windows PATH!" -ForegroundColor Red
    Write-Host "[!] Please install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "[!] IMPORTANT: Ensure you check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit 1
}

Write-Host "[+] Python environment detected: " -NoNewline -ForegroundColor Green
& $pyCmd --version

# Check requirements
& $pyCmd -c "import fastapi, uvicorn, httpx, pydantic, bs4" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Dependencies missing. Installing now from requirements.txt..." -ForegroundColor Yellow
    & $pyCmd -m pip install -r requirements.txt
}

Write-Host "[+] Starting SWA AI Web Server on http://127.0.0.1:8000 ..." -ForegroundColor Green
Write-Host "[+] Browser will open automatically. Keep this window open." -ForegroundColor Cyan
Write-Host ""

& $pyCmd run.py
