@echo off
setlocal
set APP_DIR=%~dp0
cd /d "%APP_DIR%"
python -m streamlit run Python\pcap_sentry_pro.py --global.developmentMode=false
endlocal
