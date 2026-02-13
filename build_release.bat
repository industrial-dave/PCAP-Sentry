@echo off
setlocal enabledelayedexpansion

REM Build EXE + installer with a single shared version and one GitHub release.
REM Default behavior: build EXE (which bumps version) then build installer.
REM The EXE build commits/pushes the version bump and creates the release.
REM The installer build uploads to the same release without bumping.
REM Optional: pass -NoBump to skip version update (use current version).
REM Optional: pass -Notes "your notes here" to set release notes / What's New.
REM   If omitted, defaults to "Minor tweaks and improvements".

set "NO_BUMP="
set "BUILD_NOTES=Minor tweaks and improvements"

:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="-NoBump" (
	set "NO_BUMP=1"
	shift
	goto :parse_args
)
if /I "%~1"=="-Notes" (
	set "BUILD_NOTES=%~2"
	shift
	shift
	goto :parse_args
)
shift
goto :parse_args
:args_done

if defined NO_BUMP (
	call build_exe.bat -NoBump -Notes "!BUILD_NOTES!"
) else (
	call build_exe.bat -Notes "!BUILD_NOTES!"
)
if errorlevel 1 exit /b 1

set "PCAP_NO_BUMP=1"
call build_installer.bat -NoPush -Release -Notes "!BUILD_NOTES!"
set "PCAP_NO_BUMP="
if errorlevel 1 exit /b 1

endlocal
