# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

mkdir c:/bin
mkdir c:/tmp
cd c:/tmp

function InstallOpenSSH()
{
    $sshPubKey = "SSH_PUB_KEY"
    if (!$sshPubKey) {
        Write-Output "SSH public key is omitted. Skipping OpenSSH installation."
        return
    }
    Write-Output "Installing OpenSSH"

    try {
        $rslt = ( get-service | where { $_.name -like "sshd" } )
        if ($rslt.count -eq 0) {
            $list = (Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Server*')
            if ($list) {
                Add-WindowsCapability -Online -Name $list.Name
                Install-Module -Force OpenSSHUtils
            } else {
                $open_ssh_uri = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.0p1-Beta/OpenSSH-Win64.zip"
                $open_ssh_file = "C:/tmp/OpenSSH-Win64.zip"
                & curl.exe -L -o $open_ssh_file $open_ssh_uri
                & 7z x $open_ssh_file -oC:/tmp
                c:/tmp/OpenSSH-Win64/install-sshd.ps1
            }
        }
        Start-Service sshd
        & netsh advfirewall firewall add rule name="SSH TCP Port 22" dir=in action=allow protocol=TCP localport=22

        Write-Output "Creating authorized key"
        $path = "C:\AzureData\authorized_keys"
        Set-Content -Path $path -Value $sshPubKey -Encoding Ascii

        (Get-Content C:\ProgramData\ssh\sshd_config) -replace "AuthorizedKeysFile(\s+).ssh/authorized_keys", "AuthorizedKeysFile $path" | Set-Content C:\ProgramData\ssh\sshd_config
        $acl = Get-Acl -Path $path
        $acl.SetAccessRuleProtection($True, $True)
        $acl | Set-Acl -Path $path

        $acl = Get-Acl -Path $path
        $rules = $acl.Access
        $usersToRemove = @("Everyone","BUILTIN\Users","NT AUTHORITY\Authenticated Users")
        foreach ($u in $usersToRemove) {
            $targetrule = $rules | where IdentityReference -eq $u
            if ($targetrule) {
                $acl.RemoveAccessRule($targetrule)
            }
        }
        $acl | Set-Acl -Path $path

        Restart-Service sshd

        $sshStartCmd = "C:\AzureData\OpenSSHStart.ps1"
        Set-Content -Path $sshStartCmd -Value "Start-Service sshd"

        & schtasks.exe /CREATE /F /SC ONSTART /RU SYSTEM /RL HIGHEST /TN "SSH start" /TR "powershell.exe -ExecutionPolicy Bypass -File $sshStartCmd"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to add scheduled task $sshStartCmd"
        }
    }
    catch {
       Write-Output "OpenSSH install failed: $_"
    }
}

##
#  Install git not only for git but also mingw64 including curl
#

$git_uri = "https://github.com/git-for-windows/git/releases/download/v2.19.1.windows.1/Git-2.19.1-64-bit.exe"
$git_file = "c:/tmp/git-2.19.1-64-bit.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $git_uri -Outfile $git_file
Start-Process -Wait -FilePath $git_file -ArgumentList "/silent /log:c:/tmp/git-install.log"

[Environment]::SetEnvironmentVariable("PATH", "$env:PATH;c:/program files/git/mingw64/bin;c:/program files/git/bin;c:/program files/git;c:/program files/7-zip;c:\program files\cmake\bin;C:\Program Files\ocpwin64\4.02.1+ocp1-msvc64-20160113\bin", "Machine")
[Environment]::SetEnvironmentVariable("PATH", "$env:PATH;c:/program files/git/mingw64/bin;c:/program files/git/bin;c:/program files/git;c:/program files/7-zip", "Process")
[Environment]::SetEnvironmentVariable("VS150COMNTOOLS", "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\Tools", "Machine")

##
#  Install 7zip for unpacking zip and tar files
#
$seven_zip_uri = "https://www.7-zip.org/a/7z1805-x64.msi"
$seven_zip_file = "c:/tmp/7z1805-x64.msi"
& curl.exe -o $seven_zip_file  $seven_zip_uri 
Start-Process -Wait -FilePath $seven_zip_file -ArgumentList " /quiet /passive"

#  Install OpenSSH
InstallOpenSSH

# Install the intel sgx drivers
& curl.exe  -o "c:/tmp/sgx_base.cab" "http://download.windowsupdate.com/d/msdownload/update/driver/drvs/2018/01/af564f2c-2bc5-43be-a863-437a5a0008cb_61e7ba0c2e17c87caf4d5d3cdf1f35f6be462b38.cab"
& 7z x c:/tmp/sgx_base.cab -o"c:/tmp/sgx_base" -y
&pnputil /add-driver c:/tmp/sgx_base/sgx_base.inf

$psw_uri = "http://registrationcenter-download.intel.com/akdlm/irc_nas/13688/Intel%20SGX%20PSW%20for%20Windows%20v2.1.100.46245.exe"
$psw_file = "c:/tmp/Intel%20SGX%20PSW%20for%20Windows%20v2.1.100.46245.exe"

& curl.exe -o $psw_file $psw_uri

& 7z x $psw_file -y
$psw_installer = " C:\tmp\Intel SGX PSW for Windows v2.1.100.46245\PSW\Intel(R)_SGX_Windows_x64_PSW_2.1.100.46245.exe"
Start-Process -Wait -FilePath $psw_installer -ArgumentList "--extract-folder c:/tmp/intel_psw_install --x"
Start-Process -Wait -FilePath "c:/tmp/intel_psw_install/setup" -ArgumentList "install --eula=accept --output=c:/tmp/intel_install.log --components=all"

sleep 5

try {
   Start-Service "AESMService"
}
catch {
    Write-Output "Could not start service: $_"
}

# Download useful tools to C:\Bin.
Write-Output "get nuget"
& curl.exe https://dist.nuget.org/win-x86-commandline/v4.1.0/nuget.exe -o C:\bin\nuget.exe

# Download the Build Tools bootstrapper outside of the PATH.
Write-Output "get visual stdio"
& curl.exe -L -o "C:\TMP\vs_buildtools.exe"  "https://aka.ms/vs/15/release/vs_buildtools.exe" 

Write-Output "install visual stdio"
$argslist = " -q --wait --norestart --nocache "
$argslist += "    --add Microsoft.VisualStudio.Workload.MSBuildTools "
$argslist += "    --add Microsoft.VisualStudio.Workload.VCTools "
$argslist += "    --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 "
$argslist += "    --add Microsoft.VisualStudio.Component.VC.140 "
$argslist += "    --add Microsoft.VisualStudio.Component.Windows10SDK.16299.Desktop "
$argslist += "    --add Microsoft.VisualStudio.Component.Windows81SDK "
$argslist += "    --add Microsoft.VisualStudio.Component.VC.ATL "

Start-Process -Wait -FilePath "C:\TMP\vs_buildtools.exe" -ArgumentList $argslist

$env:PATH += ";c:/program files/7-zip"

Write-Output "get cmake"
$cmake_uri = "https://cmake.org/files/v3.13/cmake-3.13.0-rc1-win64-x64.msi"
$cmake_file = "c:/tmp/cmake-3.13.0-rc1-win64-x64.msi"
& curl.exe -L -o $cmake_file $cmake_uri
Start-Process -Wait -FilePath $cmake_file -ArgumentList " /quiet /passive"

#
# ocaml for building oeedgr8r
#
Write-Output "get ocaml"
$ocaml_file = "c:/tmp/ocpwin64.zip"
$ocaml_install_dir = "c:/Program Files/ocpwin64"
$ocaml_uri  = "http://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/ocpwin64-20160113-4.02.1+ocp1-msvc64.zip"
& curl.exe -o $ocaml_file $ocaml_uri
& 7z x $ocaml_file -o"c:/Program Files/ocpwin64"
pushd "C:\Program Files\ocpwin64\4.02.1+ocp1-msvc64-20160113\bin"
& ./ocpwin -in
