@echo off
setlocal enabledelayedexpansion

REM Build a TEST version for local installation only.
REM This will:
REM   - Build EXE + installer WITHOUT bumping version
REM   - Add "-test" suffix to output files
REM   - NEVER commit to git or upload to GitHub
REM   - Skip all pre-deployment checks

echo ============================================
echo PCAP Sentry - TEST BUILD (LOCAL ONLY)
echo ============================================
echo This build will NOT:
echo   - Update the version number
echo   - Commit or push to git
echo   - Upload to GitHub
echo.
echo Test files will be created in dist\ folder
echo ============================================
echo.

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
set "LOG_PATH=%LOG_DIR%\build_test.log"
echo.> "%LOG_PATH%"
echo ==== Test Build Started %DATE% %TIME% ====>> "%LOG_PATH%"

REM Set environment to skip version bumping
set "PCAP_NO_BUMP=1"
set "PCAP_SKIP_CHECKS=1"

echo ==== Building EXE (Step 1/2) ====
echo Building EXE...>> "%LOG_PATH%"
call build_exe.bat -NoBump -NoPush -Notes "Test build - local only" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo ERROR: EXE build failed! Check %LOG_PATH% for details.
	set "PCAP_NO_BUMP="
	set "PCAP_SKIP_CHECKS="
	exit /b 1
)

echo ==== Building Installer (Step 2/2) ====
echo Building installer...>> "%LOG_PATH%"
call build_installer.bat -NoBump -NoPush -Notes "Test build - local only" >> "%LOG_PATH%" 2>&1
if errorlevel 1 (
	echo ERROR: Installer build failed! Check %LOG_PATH% for details.
	set "PCAP_NO_BUMP="
	set "PCAP_SKIP_CHECKS="
	exit /b 1
)

REM Clean up environment variables
set "PCAP_NO_BUMP="
set "PCAP_SKIP_CHECKS="

REM Rename output files to mark them as test builds
echo ==== Marking as Test Build ====
if exist "dist\PCAP_Sentry.exe" (
	if exist "dist\PCAP_Sentry_TEST.exe" del "dist\PCAP_Sentry_TEST.exe"
	copy "dist\PCAP_Sentry.exe" "dist\PCAP_Sentry_TEST.exe" >nul
	echo Created: dist\PCAP_Sentry_TEST.exe
	echo Created test EXE: dist\PCAP_Sentry_TEST.exe>> "%LOG_PATH%"
)

if exist "dist\PCAP_Sentry_Setup.exe" (
	if exist "dist\PCAP_Sentry_Setup_TEST.exe" del "dist\PCAP_Sentry_Setup_TEST.exe"
	copy "dist\PCAP_Sentry_Setup.exe" "dist\PCAP_Sentry_Setup_TEST.exe" >nul
	echo Created: dist\PCAP_Sentry_Setup_TEST.exe
	echo Created test installer: dist\PCAP_Sentry_Setup_TEST.exe>> "%LOG_PATH%"
)

echo.
echo ============================================
echo TEST BUILD COMPLETE
echo ============================================
echo.
echo Output files:
if exist "dist\PCAP_Sentry_TEST.exe" (
	for %%F in ("dist\PCAP_Sentry_TEST.exe") do echo   EXE:       %%~fF ^(%%~zF bytes^)
)
if exist "dist\PCAP_Sentry_Setup_TEST.exe" (
	for %%F in ("dist\PCAP_Sentry_Setup_TEST.exe") do echo   Installer: %%~fF ^(%%~zF bytes^)
)
echo.
echo To install:
echo   Run: dist\PCAP_Sentry_Setup_TEST.exe
echo.
echo This test build will NOT be committed or uploaded.
echo ============================================
echo.
echo Build log: %LOG_PATH%
echo.

pause
