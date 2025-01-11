# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Setup for the Windows Docker container uses the install-windows-prereqs.ps1 script.
# This script is the recommended method of installing the necessary prerequisites on
# a contributor's system, as well as the script used when creating CI images; it seemed
# like a logical choice to use the same work flow for setting up Docker containers.

ARG windows_source_repo="mcr.microsoft.com/windows/"

FROM ${windows_source_repo}servercore:ltsc2022 as build

COPY scripts/install-windows-prereqs.ps1 oe/scripts/install-windows-prereqs.ps1
ARG pip_index_url="https://pypi.org/simple"
ENV PIP_INDEX_URL=${pip_index_url}
RUN powershell.exe -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -command oe\scripts\install-windows-prereqs.ps1 -InstallPath C:\oe_prereqs -LaunchConfiguration SGX1FLC-NoIntelDrivers -DCAPClientType None -SkipTask Nuget3,Nuget6,VisualStudio,LLVM,Git,Shellcheck,NSIS,Docker,OpenSSL,VCRuntime

ARG windows_source_repo="mcr.microsoft.com/windows/"

FROM ${windows_source_repo}servercore:ltsc2022
COPY scripts/install-windows-prereqs.ps1 oe/scripts/install-windows-prereqs.ps1
COPY --from=build ["Program Files/python-3.7.4", "Program Files/python-3.7.4"]
RUN powershell.exe -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File oe\scripts\install-windows-prereqs.ps1 -InstallPath C:\oe_prereqs -LaunchConfiguration SGX1FLC-NoIntelDrivers -DCAPClientType None -SkipTask Python
RUN setx path /M "%path%;C:\Users\ContainerAdministrator\AppData\Local\Temp\packages\python3;C:\Program Files\python-3.7.4\Scripts;C:\Program Files\python-3.7.4"
