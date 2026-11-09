@echo off
rem fwmap launcher: set encoding, cd to this folder, then run py -3.13 -m fwmap
rem usage:  fwmap.cmd scan <rootfs> --top 10
rem         fwmap.cmd triage <rootfs> -o out\myfw --agent
setlocal
chcp 65001 >nul 2>nul
set "PYTHONIOENCODING=utf-8"
rem only needed by the LLM layer; harmless if missing
if exist "C:\deepseek\libs-bnb" set "PYTHONPATH=C:\deepseek\libs-bnb"
cd /d "%~dp0"
py -3.13 -m fwmap %*
if errorlevel 9009 (
  echo [!] "py -3.13" not found, falling back to python
  python -m fwmap %*
)
