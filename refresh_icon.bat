@echo off
REM ============================================================================
REM PCAP Sentry - Icon Cache Refresh Utility
REM ============================================================================
REM This script refreshes the Windows icon cache to display the updated logo.
REM Run this if the desktop shortcut still shows the old icon after an update.
REM ============================================================================

echo.
echo PCAP Sentry - Icon Cache Refresh
echo ================================
echo.
echo Refreshing Windows icon cache...
echo.

REM Method 1: IE4UINIT (fastest)
ie4uinit.exe -show >nul 2>&1

REM Method 2: Force Explorer to refresh via PowerShell
powershell -NoProfile -Command "$code = '[DllImport(\"shell32.dll\")]public static extern void SHChangeNotify(int wEventId,int uFlags,IntPtr dwItem1,IntPtr dwItem2);'; $type = Add-Type -MemberDefinition $code -Name IconRefresh -PassThru; $type::SHChangeNotify(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)" >nul 2>&1

REM Wait a moment for the refresh to take effect
timeout /t 2 /nobreak >nul

echo Done! The desktop icon should now display the updated logo.
echo.
echo If the icon is still not updated, try these additional steps:
echo   1. Right-click the desktop and select "Refresh"
echo   2. Log out and log back in to Windows
echo   3. Restart your computer
echo.
pause
