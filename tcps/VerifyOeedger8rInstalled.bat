@echo off
rem
rem Test whether oeedger8r is installed.  If not, install it.
rem
pushd %~dp0

where.exe oeedger8r.exe /q
if %errorlevel% EQU 0 goto HaveEdger8rInPath

set URI=https://oedownload.blob.core.windows.net/binaries/master/85/oeedger8r/build/output/bin/oeedger8r.exe
echo Downloading "%URI%" to "%~dp0\oeedger8r.exe"
powershell wget "%URI%" -Outfile "%~dp0\oeedger8r.exe"

:HaveEdger8rInPath
