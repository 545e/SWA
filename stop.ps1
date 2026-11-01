<#
.SYNOPSIS
    SWA AI - PowerShell Shutdown Script
.DESCRIPTION
    Cleanly shuts down the SWA AI background server using .swa.pid or port inspection.
#>

$ErrorActionPreference = "SilentlyContinue"
Set-Location -Path $PSScriptRoot

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SWA AI - Shutdown Server (PowerShell)" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

$pidFile = Join-Path $PSScriptRoot ".swa.pid"
if (Test-Path $pidFile) {
    $procId = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($procId) {
        Write-Host "[+] Terminating SWA server process (PID $procId)..." -ForegroundColor Yellow
        Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        Write-Host "[✓] SWA AI server process terminated." -ForegroundColor Green
        exit 0
    }
}

# Fallback: find listener on port 8000
$conn = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    $owningPid = $conn.OwningProcess | Select-Object -First 1
    if ($owningPid) {
        Write-Host "[+] Found listening process on port 8000 (PID $owningPid). Terminating..." -ForegroundColor Yellow
        Stop-Process -Id $owningPid -Force -ErrorAction SilentlyContinue
        Write-Host "[✓] SWA AI server stopped on port 8000." -ForegroundColor Green
        exit 0
    }
}

Write-Host "[i] No active SWA AI process detected on port 8000." -ForegroundColor Gray
