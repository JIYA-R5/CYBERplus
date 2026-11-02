@echo off
title SentinelAI - Elevated IPS Backend
echo =====================================================================
echo  SentinelAI - Automatic Intrusion Prevention System (IPS)
echo  Checking Administrator Privileges for Windows Defender Firewall...
echo =====================================================================

:: Test for administrator permissions
net session >nul 2>&1
if %errorlevel% == 0 (
    echo [*] Administrator privileges confirmed.
    echo [*] Windows Defender Firewall adapter will operate with REAL ENFORCEMENT.
    echo [*] Starting FastAPI backend on http://127.0.0.1:8000 ...
    echo.
    cd /d "%~dp0"
    python -m uvicorn api.index:app --host 127.0.0.1 --port 8000 --reload
) else (
    echo [!] Administrator privileges not detected.
    echo [!] Requesting UAC Administrator elevation...
    powershell -Command "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k title SentinelAI IPS (Elevated) && cd /d """%~dp0""" && python -m uvicorn api.index:app --host 127.0.0.1 --port 8000 --reload'"
)
