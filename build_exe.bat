@echo off
setlocal

REM Build a self-contained EXE using PyInstaller.
REM Run from repo root after activating your Python environment.

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
set "LOG_PATH=%LOG_DIR%\build_exe.log"
set "PYTHONWARNINGS=ignore:Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater:UserWarning"
echo.>> "%LOG_PATH%"
echo ==== Build started %DATE% %TIME% ====>> "%LOG_PATH%"
echo ==== System Info ====>> "%LOG_PATH%"
ver >> "%LOG_PATH%" 2>&1
python --version >> "%LOG_PATH%" 2>&1
python -c "import sys; print(sys.executable)" >> "%LOG_PATH%" 2>&1
python -m PyInstaller --version >> "%LOG_PATH%" 2>&1
echo ==== Python Packages (key) ====>> "%LOG_PATH%"
python -m pip list | findstr /I "pyinstaller scapy pandas matplotlib numpy pyarrow pillow certifi urllib3 llama-cpp-python tkinterdnd2" >> "%LOG_PATH%" 2>&1
python -m PyInstaller --noconfirm --clean "PCAP_Sentry.spec" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo EXE build failed. See %LOG_PATH% for details.
	exit /b 1
)

endlocal
