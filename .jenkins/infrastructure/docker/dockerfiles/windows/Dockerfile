# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Setup for the Windows Docker container uses the install-windows-prereqs.ps1 script.
# This script is the recommended method of installing the necessary prerequisites on
# a contributor's system, as well as the script used when creating CI images; it seemed
# like a logical choice to use the same work flow for setting up Docker containers.

FROM mcr.microsoft.com/windows/servercore:ltsc2022

COPY . oe
RUN powershell.exe -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File oe\scripts\install-windows-prereqs.ps1 -InstallPath C:\oe_prereqs -LaunchConfiguration SGX1FLC-NoIntelDrivers -DCAPClientType None
RUN del /s /q oe
