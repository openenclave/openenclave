@echo off
rem
rem Test whether the Windows Driver Kit is installed.  If not, but the
rem WinARMSDKInstallerURI environment variable is set, then fetch
rem it from there. This provides a mechanism usable by github-CI.
rem
pushd %~dp0

rem Installed WDK indicates include paths are already set.
echo Searching for installed WDK...
powershell -Command "& { Get-WmiObject -Class Win32_Product | ForEach-Object { if($_.Name -like 'Windows Driver Kit*') {echo $_; exit 123 } } }
if %errorlevel% EQU 123 goto Done

if exist External/WinARMSDK goto HaveExternalWinARMSDKDirectory
if "%WinARMSDKInstallerURI%" == "" goto TriedUri
    echo Downloading "%WinARMSDKInstallerURI%" to "%~dp0\WinARMSDK.zip"
    powershell wget "%WinARMSDKInstallerURI%" -Outfile "%~dp0\WinARMSDK.zip"
:TriedUri

if not exist %~dp0\WinARMSDK.zip goto NoWinARMSDK
unzip WinARMSDK.zip -d External
goto HaveExternalWinARMSDKDirectory

:NoWinARMSDK
echo Could not find "%~dp0\WinARMSDK.zip"
goto Done

:HaveExternalWinARMSDKDirectory
set WinARMSDKInstallPath=%~dp0\External\WinARMSDK
goto Done

:Done
if exist %WinARMSDKInstallPath% echo VerifySgxSdkinstalled: WinARMSDKInstallPath is %WinARMSDKInstallPath%
popd