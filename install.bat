@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title SWA AI — Installation & Setup

echo ===================================================
echo   SWA AI - Autonomous Cyber Tool Suite Installer
echo ===================================================
echo.

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Python 3 is not found in your PATH!
    echo [!] Please install Python 3.10+ from https://www.python.org/downloads/
    echo [!] Ensure you check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [+] Python environment detected.
python --version

:: Upgrade pip
echo [+] Upgrading pip...
python -m pip install --upgrade pip

:: Install dependencies
echo [+] Installing SWA dependencies from requirements.txt...
python -m pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo  [v] SWA AI successfully installed!
    echo  Starting SWA AI Dashboard automatically...
    echo  (Opening http://127.0.0.1:8000 in your browser)
    echo ===================================================
    echo.
    echo Starting server in 2 seconds...
    timeout /t 2 >nul 2>&1
    call run.bat
) else (
    echo.
    echo [-] Dependency installation encountered an issue.
    echo [!] Try running: pip install -r requirements.txt manually.
    pause
)
