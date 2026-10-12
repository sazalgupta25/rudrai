@echo off
setlocal
set "SCRIPT=%~dp0scripts\uninstall-local.ps1"
set "UNINSTALL_ARGS="

if not exist "%SCRIPT%" (
  echo RudrAI uninstall script was not found:
  echo %SCRIPT%
  pause
  exit /b 1
)

echo Starting RudrAI local uninstall...
if /I "%~1"=="pip" set "UNINSTALL_ARGS=-UninstallPipPackage"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %UNINSTALL_ARGS%
set "UNINSTALL_EXIT=%ERRORLEVEL%"

if not "%UNINSTALL_EXIT%"=="0" (
  echo.
  echo Uninstall did not complete. Review the message above and try again.
) else (
  echo.
  echo RudrAI local installation removed.
)
pause
exit /b %UNINSTALL_EXIT%
