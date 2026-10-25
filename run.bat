@echo off
setlocal
cd /d "%~dp0"
title SWA AI — Cybersecurity Platform & Dashboard

echo ===================================================
echo   SWA AI - Security Operations Center & Cyber Hub
echo ===================================================
echo.

:: Check python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Python 3 is not found in your PATH!
    echo [!] Please install Python 3.10+ from https://www.python.org/downloads/
    echo [!] Ensure you check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Auto check essential dependencies
python -c "import fastapi, uvicorn, httpx, pydantic, bs4" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python dependencies missing. Installing now from requirements.txt...
    python -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [-] Failed to install dependencies automatically.
        echo [!] Please run: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo [+] Starting SWA AI Web Server...
echo [+] The dashboard will automatically open in your default browser.
echo [+] IMPORTANT: Keep this command prompt window OPEN while using SWA.
echo.

python run.py

if %errorlevel% neq 0 (
    echo.
    echo [-] SWA server exited with code %errorlevel%.
    pause
)
