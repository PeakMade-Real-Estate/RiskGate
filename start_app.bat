@echo off
cd /d "%~dp0"
title RiskGate Local App
set RISKGATE_LOCAL_HTTP=true
"%~dp0.venv\Scripts\python.exe" run.py
