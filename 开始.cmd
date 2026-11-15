@echo off
rem GUI entry point. Double-click this file.
rem Keep this file ASCII-only: cmd.exe parses .cmd in the OEM codepage,
rem so non-ASCII text here gets mangled before chcp can take effect.
setlocal
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "PY="

py -3.13 -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3.13"
if defined PY goto run

py -3 -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto run

python -c "import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto run

echo.
echo   Python 3.11 or newer not found.
echo   Install it from https://www.python.org/downloads/
echo   (tick "Add python.exe to PATH" during setup)
echo.
pause
exit /b 1

:run
%PY% -X utf8 -m fwmap app %*
if errorlevel 1 pause
exit /b 0
