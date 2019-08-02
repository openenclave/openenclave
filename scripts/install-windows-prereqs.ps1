# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Param(
    [string]$GitURL = 'https://github.com/git-for-windows/git/releases/download/v2.19.1.windows.1/Git-2.19.1-64-bit.exe',
    [string]$SevenZipURL = 'https://www.7-zip.org/a/7z1806-x64.msi',
    [string]$VSBuildToolsURL = 'https://aka.ms/vs/15/release/vs_buildtools.exe',
    [string]$OCamlURL = 'https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/ocpwin64-20160113-4.02.1+ocp1-mingw64.zip',
    [string]$Clang7URL = 'http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe',
    [string]$IntelPSWURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/15369/Intel%20SGX%20PSW%20for%20Windows%20v2.3.100.49777.exe',
    [string]$ShellCheckURL = 'https://storage.googleapis.com/shellcheck/shellcheck-stable.exe',
    [string]$NugetURL = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe',
    [string]$DevconURL = 'https://download.microsoft.com/download/7/D/D/7DD48DE6-8BDA-47C0-854A-539A800FAA90/wdk/Installers/787bee96dbd26371076b37b13c405890.cab',
    [string]$IntelDCAPURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/15384/Intel%20SGX%20DCAP%20for%20Windows%20v1.1.100.49925.exe',
    [string]$VCRuntime2012URL = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe',
    [string]$AzureDCAPNupkgURL = 'https://oejenkins.blob.core.windows.net/oejenkins/Microsoft.Azure.DCAP.Client.1.0.0.nupkg' # TODO: Update this to official link once this is available
    [string]$Python3URL = 'https://www.python.org/ftp/python/3.7.4/python-3.7.4.exe'
)

$ErrorActionPreference = "Stop"

$PACKAGES_DIRECTORY = Join-Path $env:TEMP "packages"
$OE_NUGET_DIR = Join-Path ${env:SystemDrive} "openenclave\prereqs\nuget"

$PACKAGES = @{
    "git" = @{
        "url" = $GitURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Git-64-bit.exe"
    }
    "7z" = @{
        "url" = $SevenZipURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "7z-x64.msi"
    }
    "vs_buildtools" = @{
        "url" = $VSBuildToolsURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "vs_buildtools.exe"
    }
    "ocaml" = @{
        "url" = $OCamlURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "ocpwin64.zip"
    }
    "clang7" = @{
        "url" = $Clang7URL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "LLVM-win64.exe"
    }
    "psw" = @{
        "url" = $IntelPSWURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_PSW_for_Windows.exe"
    }
    "shellcheck" = @{
        "url" = $ShellCheckURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "shellcheck.exe"
    }
    "nuget" = @{
        "url" = $NugetURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "nuget.exe"
    }
    "devcon" = @{
        "url" = $DevconURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "devcon_package.cab"
    }
    "dcap" = @{
        "url" = $IntelDCAPURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_DCAP.exe"
    }
    "vc_runtime_2012" = @{
        "url" = $VCRuntime2012URL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "vcredist_x64.exe"
    }
    "azure_dcap_client_nupkg" = @{
        "url" = $AzureDCAPNupkgURL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Microsoft.Azure.DCAP.Client.1.0.0.nupkg"
    }
    "python3" = @{
        "url" = $Python3URL
        "local_file" = Join-Path $PACKAGES_DIRECTORY "python-3.4.7.exe"
    }
}

filter Timestamp { "[$(Get-Date -Format o)] $_" }

function Write-Log {
    Param(
        [string]$Message
    )
    $msg = $Message | Timestamp
    Write-Output $msg
}

function New-Directory {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [switch]$RemoveExisting
    )
    if(Test-Path $Path) {
        if($RemoveExisting) {
            # Remove if it already exist
            Remove-Item -Recurse -Force $Path
        } else {
            return
        }
    }
    return (New-Item -ItemType Directory -Path $Path)
}

function Start-LocalPackagesDownload {
    Write-Output "Downloading all the packages to local directory: $PACKAGES_DIRECTORY"
    New-Directory $PACKAGES_DIRECTORY -RemoveExisting
    foreach($pkg in $PACKAGES.Keys) {
        Write-Output "Downloading: $($PACKAGES[$pkg]["url"])"
        Start-FileDownload -URL $PACKAGES[$pkg]["url"] `
                           -Destination $PACKAGES[$pkg]["local_file"]
    }
    Write-Output "Finished downloading all the packages"
}

function Start-ExecuteWithRetry {
    Param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,
        [int]$MaxRetryCount=10,
        [int]$RetryInterval=3,
        [string]$RetryMessage,
        [array]$ArgumentList=@()
    )
    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $retryCount = 0
    while ($true) {
        Write-Log "Start-ExecuteWithRetry attempt $retryCount"
        try {
            $res = Invoke-Command -ScriptBlock $ScriptBlock `
                                  -ArgumentList $ArgumentList
            $ErrorActionPreference = $currentErrorActionPreference
            Write-Log "Start-ExecuteWithRetry terminated"
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -gt $MaxRetryCount) {
                $ErrorActionPreference = $currentErrorActionPreference
                Write-Log "Start-ExecuteWithRetry exception thrown"
                throw
            } else {
                if($RetryMessage) {
                    Write-Log "Start-ExecuteWithRetry RetryMessage: $RetryMessage"
                } elseif($_) {
                    Write-Log "Start-ExecuteWithRetry Retry: $_.ToString()"
                }
                Start-Sleep $RetryInterval
            }
        }
    }
}

function Start-FileDownload {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        [Parameter(Mandatory=$false)]
        [int]$RetryCount=10
    )
    Start-ExecuteWithRetry -ScriptBlock {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($URL, $Destination)
    } -MaxRetryCount $RetryCount -RetryInterval 3 -RetryMessage "Failed to download $URL. Retrying"
}

function Add-ToSystemPath {
    Param(
        [Parameter(Mandatory=$false)]
        [string[]]$Path
    )
    if(!$Path) {
        return
    }
    $systemPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine').Split(';')
    $currentPath = $env:PATH.Split(';')
    foreach($p in $Path) {
        if($p -notin $systemPath) {
            $systemPath += $p
        }
        if($p -notin $currentPath) {
            $currentPath += $p
        }
    }
    $env:PATH = $currentPath -join ';'
    setx.exe /M PATH ($systemPath -join ';')
    if($LASTEXITCODE) {
        Throw "Failed to set the new system path"
    }
}

function Install-Tool {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath,
        [Parameter(Mandatory=$false)]
        [string]$InstallDirectory,
        [Parameter(Mandatory=$false)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory=$false)]
        [string[]]$EnvironmentPath
    )
    if($InstallDirectory -and (Test-Path $InstallDirectory)) {
        Write-Output "$InstallerPath is already installed."
        Add-ToSystemPath -Path $EnvironmentPath
        return
    }
    $parameters = @{
        'FilePath' = $InstallerPath
        'Wait' = $true
        'PassThru' = $true
    }
    if($ArgumentList) {
        $parameters['ArgumentList'] = $ArgumentList
    }
    if($InstallerPath.EndsWith('.msi')) {
        $parameters['FilePath'] = 'msiexec.exe'
        $parameters['ArgumentList'] = @("/i", $InstallerPath) + $ArgumentList
    }
    Write-Output "Installing $InstallerPath"
    $p = Start-Process @parameters
    if($p.ExitCode -ne 0) {
        Throw "Failed to install: $InstallerPath"
    }
    Add-ToSystemPath -Path $EnvironmentPath
    Write-Output "Successfully installed: $InstallerPath"
}

function Install-ZipTool {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ZipPath,
        [Parameter(Mandatory=$true)]
        [string]$InstallDirectory,
        [Parameter(Mandatory=$false)]
        [string[]]$EnvironmentPath
    )
    if(Test-Path $InstallDirectory) {
        Write-Output "$ZipPath is already installed."
        Add-ToSystemPath -Path $EnvironmentPath
        return
    }
    New-Item -ItemType "Directory" -Path $InstallDirectory
    7z.exe x $ZipPath -o"$InstallDirectory" -y
    if($LASTEXITCODE) {
        Throw "ERROR: Failed to extract $ZipPath to $InstallDirectory"
    }
    Add-ToSystemPath $EnvironmentPath
}

function Install-Git {
    $installDir = Join-Path $env:ProgramFiles "Git"
    Install-Tool -InstallerPath $PACKAGES["git"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/SILENT") `
                 -EnvironmentPath @("$installDir\cmd", "$installDir\bin", "$installDir\mingw64\bin")
}

function Install-7Zip {
    $installDir = Join-Path $env:ProgramFiles "7-Zip"
    Install-Tool -InstallerPath $PACKAGES["7z"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/quiet", "/passive") `
                 -EnvironmentPath @($installDir)
}

function Install-PSW {
    $tempInstallDir = "$PACKAGES_DIRECTORY\Intel_SGX_PSW"
    if(Test-Path $tempInstallDir) {
        Remove-Item -Recurse -Force $tempInstallDir
    }
    Install-ZipTool -ZipPath $PACKAGES["psw"]["local_file"] `
                    -InstallDirectory $tempInstallDir

    $installer = Get-Item "$tempInstallDir\Intel*SGX*\PSW_EXE*\Intel(R)_SGX_Windows_x64_PSW_*.exe"
    if(!$installer) {
        Throw "Cannot find the installer executable"
    }
    if($installer.Count -gt 1) {
        Throw "Multiple installer executables found"
    }
    $unattendedParams = @('--s', '--a', 'install', "--output=$tempInstallDir\psw-installer.log", '--eula=accept', '--no-progress')
    $p = Start-Process -Wait -NoNewWindow -FilePath $installer -ArgumentList $unattendedParams -PassThru
    if($p.ExitCode -ne 0) {
        Get-Content "$tempInstallDir\psw-installer.log"
        Throw "Failed to install Intel PSW"
    }

    Start-ExecuteWithRetry -ScriptBlock {
        Start-Service "AESMService" -ErrorAction Stop
    } -RetryMessage "Failed to start AESMService. Retrying"
}

function Install-VisualStudio {
    $installerArguments = @(
        "-q", "--wait", "--norestart",
        "--add Microsoft.VisualStudio.Workload.VCTools",
        "--add Microsoft.VisualStudio.Component.VC.CMake.Project"
        "--add Microsoft.VisualStudio.Component.Windows10SDK.17134"
        "--add Microsoft.VisualStudio.Component.VC.v141.ARM.Spectre"
        "--add Microsoft.VisualStudio.Component.VC.v141.ARM64.Spectre"
        "--includeRecommended"
    )

    Install-Tool -InstallerPath $PACKAGES["vs_buildtools"]["local_file"] `
                -ArgumentList $installerArguments `
                -EnvironmentPath @("${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build", `
                                   "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\BuildTools\Common7\Tools")
}

function Install-OCaml {
    $installDir = Join-Path $env:ProgramFiles "OCaml"
    $tmpDir = Join-Path $PACKAGES_DIRECTORY "ocpwin64"
    if(Test-Path -Path $tmpDir) {
        Remove-Item -Recurse -Force -Path $tmpDir
    }
    Install-ZipTool -ZipPath $PACKAGES["ocaml"]["local_file"] `
                    -InstallDirectory $tmpDir `
                    -EnvironmentPath @("$installDir\bin")
    New-Directory -Path $installDir -RemoveExisting
    Move-Item -Path "$tmpDir\*\*" -Destination $installDir
}
function Install-LLVM {
    Install-Tool -InstallerPath $PACKAGES["clang7"]["local_file"] `
                 -ArgumentList "/S" `
                 -EnvironmentPath "${env:ProgramFiles}\LLVM\bin"
}

function Install-Shellcheck {
    $shellcheckDest = Join-Path $env:ProgramFiles "shellcheck"
    if(Test-Path -Path $shellcheckDest) {
        Remove-Item -Path $shellcheckDest -Force -Recurse
    }
    New-Item -ItemType Directory -Path $shellcheckDest
    Move-Item "$PACKAGES_DIRECTORY\shellcheck.exe" $shellcheckDest -Force
    Add-ToSystemPath -Path "${env:ProgramFiles}\shellcheck"
}

function Get-DevconBinary {
    $devConBinaryPath = Join-Path $PACKAGES_DIRECTORY "devcon.exe"
    if(Test-Path $devConBinaryPath) {
        return $devConBinaryPath
    }
    #Extract devcon.exe from the cab
    $cabPkg = Join-Path $PACKAGES_DIRECTORY "devcon_package.cab"
    if(!(Test-Path $cabPkg)) {
        Throw "Cannot find DevCon pkg file: $cabPkg"
    }
    $devConFileName = "filbad6e2cce5ebc45a401e19c613d0a28f"
    $result = expand.exe $cabPkg -F:$devConFileName $PACKAGES_DIRECTORY
    if($LASTEXITCODE) {
        Throw "Failed to expand DevCon cab file"
    }
    $devConFile = Join-Path $PACKAGES_DIRECTORY $devConFileName

    Move-Item $devConFile $devConBinaryPath -Force
    return $devConBinaryPath
}

function Remove-DCAPDriver {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $devConPath = Get-DevconBinary
    $output = & $devConPath remove $Name
    if($LASTEXITCODE -eq 1) {
        #
        # Unfortunately, the exit code is 1 even when the operation was
        # successful, but a reboot is required. So, we parse the output
        # to see if a reboot was requested.
        #
        foreach($line in $output) {
            if($line.Contains("Removed on reboot")) {
                Write-Output $output
                return 0
            }
        }
        #
        # If we reach this point, it means that the exit code was 1 and
        # no reboot is needed. Therefore, most probably an error occured.
        #
        Write-Output $output
        throw "ERROR: Failed to remove $Name"
    } elseif($LASTEXITCODE -ne 0) {
        Write-Output $output
        throw "ERROR: Unknown exit code $LASTEXITCODE"
    }
    Write-Output $output
    return 0
}


function Install-DCAPDrivers {
    Install-Tool -InstallerPath $PACKAGES["dcap"]["local_file"] `
                 -ArgumentList @('/auto', "$PACKAGES_DIRECTORY\Intel_SGX_DCAP")

    $drivers = @{
        'sgx_base_dev' = @{
            'zip_path'    = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\LC_driver_WinServer2016\Signed_*.zip"
            'location'    = 'root\SgxLCDevice'
            'description' = 'Intel(R) Software Guard Extensions Launch Configuration Service'
        }
        'sgx_dcap_dev' = @{
            'zip_path'    = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\DCAP_INF\WinServer2016\Signed_*.zip"
            'location'    = 'root\SgxLCDevice_DCAP'
            'description' = 'Intel(R) Software Guard Extensions DCAP Components Device'
        }
    }
    $devConBinaryPath = Get-DevconBinary
    foreach($driver in $drivers.Keys) {
        $zip = Get-Item $drivers[$driver]['zip_path']
        if(!$zip) {
            Throw "Cannot find the zile file with $driver"
        }
        if($zip.Count -gt 1) {
            $zip
            Throw "Multiple driver zip files found"
        }
        New-Item -ItemType Directory -Force -Path "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver"
        Expand-Archive -Path $zip -DestinationPath "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver" -Force
        $inf = Get-Item "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver\drivers\*\$driver.inf"
        if(!$inf) {
            Throw "Cannot find $driver.inf file"
        }
        if($inf.Count -gt 1) {
            $inf
            Throw "Multiple $driver.inf files found"
        }
        # Check if the driver is already installed and delete it
        $output = & $devConBinaryPath find "$($drivers[$driver]['location'])"
        if($LASTEXITCODE) {
            Throw "Failed searching for $driver driver"
        }
        $output | ForEach-Object {
            if($_.Contains($drivers[$driver]['description'])) {
                Write-Output "Removing driver $($drivers[$driver]['location'])"
                Remove-DCAPDriver -Name $drivers[$driver]['location']
            }
        }
        Write-Output "Installing driver $($drivers[$driver]['location'])"
        $install = & $devConBinaryPath install "$($inf.FullName)" $drivers[$driver]['location']
        if($LASTEXITCODE) {
            Throw "Failed to install $driver driver"
        }
        Write-Output $install
    }
    $TEMP_NUGET_DIR = "$PACKAGES_DIRECTORY\Azure_DCAP_Client_nupkg"
    New-Directory -Path $OE_NUGET_DIR -RemoveExisting
    New-Directory -Path $TEMP_NUGET_DIR -RemoveExisting
    $nupkgDir = Get-Item "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\nupkg"
    if(!$nupkgDir) {
        Throw "Cannot find the Intel DCAP nupkg directory"
    }
    if($nupkgDir.Count -gt 1) {
        Throw "Multiple Intel DCAP nupkg directories found"
    }
    Copy-Item -Recurse -Force "$nupkgDir\*" $TEMP_NUGET_DIR
    Copy-Item $PACKAGES['azure_dcap_client_nupkg']['local_file'] -Destination $TEMP_NUGET_DIR -Force
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'EnclaveCommonAPI' -Source "$TEMP_NUGET_DIR" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget EnclaveCommonAPI"
    }
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'DCAP_Components' -Source "$TEMP_NUGET_DIR" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget DCAP_Components"
    }
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'Microsoft.Azure.DCAP.Client' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget Microsoft.Azure.DCAP.Client"
    }

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters" -Name "SGX_Launch_Config_Optin" -Value 1 -PropertyType DWORD -Force
}

function Install-VCRuntime {
    Write-Log "Installing VC 2012 runtime"
    $p = Start-Process -Wait -PassThru -FilePath $PACKAGES["vc_runtime_2012"]["local_file"] -ArgumentList @("/install", "/passive")
    if($p.ExitCode -ne 0) {
        Throw ("Failed to install VC 2012 runtime. Exit code: {0}" -f $p.ExitCode)
    }
}

function Install-Python3 {
    Write-Log "Installing Python3"
    $tmpDir = Join-Path $PACKAGES_DIRECTORY "Python3"
    $envPath = Join-Path "$PACKAGES_DIRECTORY\..\.." "Programs\Python\Python37-32"
    Install-Tool -InstallerPath $PACKAGES["python3"]["local_file"] `
                 -InstallDirectory $tmpDir `
                 -ArgumentList @("/quiet", "/passive") `
                 -EnvironmentPath @($envPath)
}

try {
    Start-LocalPackagesDownload

    Install-7Zip
    Install-VisualStudio
    Install-LLVM
    Install-Git
    Install-OCaml
    Install-Shellcheck
    Install-PSW
    Install-DCAPDrivers
    Install-VCRuntime
    Install-Python3

    Write-Output 'Please reboot your computer for the configuration to complete.'
} catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    Exit 1
} finally {
    Remove-Item -Recurse -Force $PACKAGES_DIRECTORY -ErrorAction SilentlyContinue
}
Exit 0
