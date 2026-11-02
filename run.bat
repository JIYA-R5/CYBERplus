@echo off
title SentinelAI - Autonomous SOC
cd /d "%~dp0"
echo ====================================================
echo Starting SentinelAI Full Web Platform...
echo ====================================================
echo 1. Full React Web App:   http://127.0.0.1:8000
echo 2. Streamlit Dashboard:  http://localhost:8501
echo ====================================================
start "SentinelAI API + Web App" .venv\Scripts\uvicorn.exe api.index:app --host 127.0.0.1 --port 8000
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8000
