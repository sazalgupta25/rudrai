@echo off
setlocal
set "SCRIPT=%~dp0scripts\setup-local.ps1"

if not exist "%SCRIPT%" (
  echo RudrAI setup script was not found:
  echo %SCRIPT%
  pause
  exit /b 1
)

echo Starting RudrAI local setup...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "SETUP_EXIT=%ERRORLEVEL%"

if not "%SETUP_EXIT%"=="0" (
  echo.
  echo Setup did not complete. Review the message above and correct the issue before trying again.
) else (
  echo.
  echo Setup complete. Close and reopen PowerShell before using the rudrai command.
)
pause
exit /b %SETUP_EXIT%
