@echo off
setlocal
set APP_DIR=%~dp0
cd /d "%APP_DIR%"
set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
%PYTHON% Python\pcap_sentry_gui.py
endlocal
