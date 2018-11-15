@echo off
rem
rem Test whether the Intel SGX SDK is installed.  If not, but the
rem IntelSGXSDKInstallerURI environment variable is set, then fetch
rem it from there. This provides a mechanism usable by github-CI.
rem
pushd %~dp0

where.exe sgx_edger8r.exe /q
if %errorlevel% EQU 0 goto HaveEdger8rInPath

if exist ..\3rdparty\SGXSDK goto HaveExternalSGXSDKDirectory
if "%IntelSGXSDKInstallerURI%" == "" goto TriedUri
    echo Downloading "%IntelSGXSDKInstallerURI%" to "%~dp0\SGXSDK.zip"
    powershell wget "%IntelSGXSDKInstallerURI%" -Outfile "%~dp0\SGXSDK.zip"
:TriedUri

if not exist %~dp0\SGXSDK.zip goto NoSGXSDK
unzip SGXSDK.zip -d ..\3rdparty
goto HaveExternalSGXSDKDirectory

:NoSGXSDK
echo Could not find "%~dp0\SGXSDK.zip"
goto Done

:HaveExternalSGXSDKDirectory
set SGXSDKInstallPath=%~dp0\..\3rdparty\SGXSDK
set PATH=%PATH%;%SGXSDKInstallPath%\bin\win32\Release
echo Set PATH to %PATH%
goto Done

:HaveEdger8rInPath
FOR /F "tokens=* USEBACKQ" %%F IN (`where sgx_edger8r.exe`) DO (
SET Edger8rPath=%%F
)
if "%SGXSDKInstallPath%" NEQ "" goto HaveIntelSGXSDK
    pushd %Edger8rPath%\..\..\..\..
    set SGXSDKInstallPath=%cd%
    popd

:HaveIntelSGXSDK
if exist ..\3rdparty\SGXSDK goto Done
mklink /d /j ..\3rdparty\SGXSDK "%SGXSDKInstallPath%" > NUL

:Done
echo VerifySgxSdkinstalled: SGXSDKInstallPath is %SGXSDKInstallPath%
VerifyOeedger8rInstalled.bat
popd
