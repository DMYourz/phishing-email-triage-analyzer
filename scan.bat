@echo off
REM ============================================================
REM  Phishing Email Triage Scanner - drag-and-drop launcher
REM  Usage:
REM    * Drag an .eml file (or a folder of them) onto this file
REM    * Or double-click and paste a path when prompted
REM    * Or from any terminal:  scan.bat "C:\path\to\email.eml"
REM ============================================================
setlocal enabledelayedexpansion
title Phishing Email Triage Scanner

set "PROJ=%~dp0"
set "TARGET=%~1"

if "%TARGET%"=="" (
  echo Drag an .eml file onto this scanner, or paste a path below.
  set /p "TARGET=Path to .eml file or folder: "
)
if "%TARGET%"=="" goto :end

REM Resolve the file stem so we can open the right report afterwards
for %%F in ("%TARGET%") do set "STEM=%%~nF"

pushd "%PROJ%"
if exist "%TARGET%\" (
  echo Scanning folder: %TARGET%
  python -m phishtriage batch "%TARGET%" -o "%PROJ%reports"
  start "" "%PROJ%reports\SUMMARY.md"
) else (
  echo Scanning file: %TARGET%
  python -m phishtriage analyze "%TARGET%" -f all -o "%PROJ%reports"
  if exist "%PROJ%reports\!STEM!.report.html" start "" "%PROJ%reports\!STEM!.report.html"
)
popd

:end
echo.
echo Done. Reports are in: %PROJ%reports
pause
