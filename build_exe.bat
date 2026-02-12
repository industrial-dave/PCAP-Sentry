@echo off
setlocal

REM Build a self-contained EXE using PyInstaller.
REM Run from repo root after activating your Python environment.

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
set "LOG_PATH=%LOG_DIR%\build_exe.log"
set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
set "PYTHONWARNINGS=ignore:Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater:UserWarning"
echo.>> "%LOG_PATH%"
echo ==== Build started %DATE% %TIME% ====>> "%LOG_PATH%"

REM Update version before build
echo ==== Updating Version ====>> "%LOG_PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -File "update_version.ps1" -BuildNotes "Rebuild artifacts" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Failed to update version. See %LOG_PATH% for details.
	exit /b 1
)
echo ==== System Info ====>> "%LOG_PATH%"
ver >> "%LOG_PATH%" 2>&1
%PYTHON% --version >> "%LOG_PATH%" 2>&1
%PYTHON% -c "import sys; print(sys.executable)" >> "%LOG_PATH%" 2>&1
%PYTHON% -m PyInstaller --version >> "%LOG_PATH%" 2>&1
%PYTHON% -c "import scapy" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Scapy is missing in the build environment. Install it and retry.
	exit /b 1
)
%PYTHON% -c "import sklearn, joblib" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo scikit-learn/joblib is missing in the build environment. Install it and retry.
	exit /b 1
)
echo ==== Python Packages (key) ====>> "%LOG_PATH%"
%PYTHON% -m pip list | findstr /I "pyinstaller scapy pandas matplotlib numpy pyarrow pillow certifi urllib3 tkinterdnd2" >> "%LOG_PATH%" 2>&1
%PYTHON% -m PyInstaller --noconfirm --clean "PCAP_Sentry.spec" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo EXE build failed. See %LOG_PATH% for details.
	exit /b 1
)

endlocal
