@echo off
setlocal

REM Builds the installer using Inno Setup.
REM Run this after building the EXE.

set "ISCC_EXE="
for %%I in (iscc.exe) do set "ISCC_EXE=%%~$PATH:I"

if not defined ISCC_EXE (
	if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC_EXE=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
)

if not defined ISCC_EXE (
	if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC_EXE=%ProgramFiles%\Inno Setup 6\ISCC.exe"
)

if not defined ISCC_EXE (
	if exist "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe" set "ISCC_EXE=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
)

if not defined ISCC_EXE (
	echo Inno Setup not found. Install it or add ISCC.exe to PATH.
	exit /b 1
)

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
set "LOG_PATH=%LOG_DIR%\build_installer.log"
set "PYTHON=python"
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
echo.>> "%LOG_PATH%"
echo ==== Build started %DATE% %TIME% ====>> "%LOG_PATH%"

REM Update version before build
echo ==== Updating Version ====>> "%LOG_PATH%"
powershell -NoProfile -ExecutionPolicy Bypass -File "update_version.ps1" -BuildNotes "Installer build" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Failed to update version. See %LOG_PATH% for details.
	exit /b 1
)
echo ==== System Info ====>> "%LOG_PATH%"
ver >> "%LOG_PATH%" 2>&1
echo ISCC_EXE=%ISCC_EXE%>> "%LOG_PATH%"
"%ISCC_EXE%" /? >> "%LOG_PATH%" 2>&1
echo ==== Python Packages (key) ====>> "%LOG_PATH%"
%PYTHON% -m pip list | findstr /I "pyinstaller scapy pandas matplotlib numpy pyarrow pillow certifi urllib3 tkinterdnd2" >> "%LOG_PATH%" 2>&1
"%ISCC_EXE%" installer\PCAP_Sentry.iss >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo Installer build failed. See %LOG_PATH% for details.
	exit /b 1
)

endlocal
