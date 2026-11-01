@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title SWA AI - Stop Server

echo ===================================================
echo   SWA AI - Shutdown Server
echo ===================================================
echo.

if exist ".swa.pid" (
    set /p SWA_PID=<.swa.pid
    echo [+] Found SWA AI PID: !SWA_PID!
    taskkill /PID !SWA_PID! /F /T >nul 2>&1
    del /f /q ".swa.pid" >nul 2>&1
    echo [✓] SWA AI server stopped successfully.
    goto :done
)

echo [i] No .swa.pid file found. Checking for processes listening on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    set TARGET_PID=%%a
    if defined TARGET_PID (
        echo [+] Stopping process on port 8000 (PID !TARGET_PID!)...
        taskkill /PID !TARGET_PID! /F /T >nul 2>&1
        echo [✓] Stopped SWA process on port 8000.
        goto :done
    )
)

echo [i] No active SWA AI server found running on port 8000.

:done
echo.
