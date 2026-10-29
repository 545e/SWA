@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title SWA AI - Installation and Setup

echo ===================================================
echo   SWA AI - Autonomous Cyber Tool Suite Installer
echo ===================================================
echo.

:: Detect Python executable
set "PY_CMD="
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=python"
) else (
    py -3 --version >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=py -3"
    ) else (
        python3 --version >nul 2>&1
        if %errorlevel% equ 0 (
            set "PY_CMD=python3"
        )
    )
)

if "%PY_CMD%"=="" (
    echo [-] Python 3 was not found in your Windows PATH!
    echo [!] Please install Python 3.10+ from https://www.python.org/downloads/
    echo [!] IMPORTANT: Check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [+] Python environment detected:
%PY_CMD% --version
echo.

:: Initialize .env if missing
if not exist ".env" (
    if exist ".env.example" (
        echo [+] Initializing default .env from .env.example...
        copy ".env.example" ".env" >nul 2>&1
    )
)

:: Upgrade pip
echo [+] Upgrading pip...
%PY_CMD% -m pip install --upgrade pip

:: Install dependencies
echo [+] Installing SWA dependencies from requirements.txt...
%PY_CMD% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo [-] Dependency installation encountered an issue.
    echo [!] Try running manually: %PY_CMD% -m pip install -r requirements.txt
    pause
    exit /b 1
)

:: Register swa console command locally
echo [+] Registering swa CLI command in system...
%PY_CMD% -m pip install -e .

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo  [v] SWA AI successfully installed and configured!
    echo  [v] 'swa' command registered for terminal usage.
    echo  Starting SWA AI Dashboard automatically...
    echo  (Opening http://127.0.0.1:8000 in your browser)
    echo ===================================================
    echo.
    echo Starting server in 2 seconds...
    timeout /t 2 >nul 2>&1
    call run.bat
) else (
    echo.
    echo [-] Editable package registration encountered an issue.
    echo [!] You can still run directly using: %PY_CMD% run.py
    pause
)
