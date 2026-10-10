@echo off
setlocal
set "RUDRAI_EXE=%~dp0.rudrai-pipx\bin\rudrai.exe"

if not exist "%RUDRAI_EXE%" (
  echo RudrAI is not installed in this checkout. Run Setup-RudrAI.cmd first.
  exit /b 3
)

"%RUDRAI_EXE%" %*
exit /b %ERRORLEVEL%
