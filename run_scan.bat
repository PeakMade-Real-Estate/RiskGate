@echo off
REM Batch wrapper for RiskGate security scan
REM This handles paths with spaces correctly for Task Scheduler

cd /d "Z:\Shared\Technology\AI Projects\RiskGate"
"Z:\Shared\Technology\AI Projects\RiskGate\.venv\Scripts\python.exe" run_security_scan.py
