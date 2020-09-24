# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# The Hash parameter defaults below are calculated using Get-FileHash with the default SHA256 hashing algorithm
Param(
    # We skip the hash check for the vs_buildtools.exe file because it is regularly updated without a change to the URL, unfortunately.
    [string]$IntelPSWURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/16899/Intel%20SGX%20PSW%20for%20Windows%20v2.9.100.2.exe',
    [string]$IntelPSWHash = 'A2F357F3AC1629C2A714A05DCA14CF8C7F25868A0B3352FAE351B14AD121BDFC',
    [string]$DevconURL = 'https://download.microsoft.com/download/7/D/D/7DD48DE6-8BDA-47C0-854A-539A800FAA90/wdk/Installers/787bee96dbd26371076b37b13c405890.cab',
    [string]$DevconHash = 'A38E409617FC89D0BA1224C31E42AF4344013FEA046D2248E4B9E03F67D5908A',
    [string]$IntelDCAPURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/16928/Intel%20SGX%20DCAP%20for%20Windows%20v1.8.100.2.exe',
    [string]$IntelDCAPHash = 'F45D12351A1839C6F1AF58CC53D64B0810BC12E7DFF0E9DBF80A0031754AA925',
    [string]$AzureDCAPNupkgURL = 'https://www.nuget.org/api/v2/package/Microsoft.Azure.DCAP/1.6.0',
    [string]$AzureDCAPNupkgHash = 'CC6D4071CE03B9E6922C3265D99FB1C0E56FCDB3409CBCEDB5A76F4886A3964A',
    [Parameter(mandatory=$true)][string]$InstallPath,
    [Parameter(mandatory=$true)][ValidateSet("SGX1FLC", "SGX1", "SGX1FLC-NoIntelDrivers", "SGX1-NoIntelDrivers")][string]$LaunchConfiguration,
    [Parameter(mandatory=$true)][ValidateSet("None", "Azure")][string]$DCAPClientType,
    [Parameter(mandatory=$false)][ValidateSet("CICD", "None")][string]$ImageConfiguration
)

$ErrorActionPreference = "Stop"

$PACKAGES_DIRECTORY = Join-Path $env:TEMP "packages"
$OE_NUGET_DIR = $InstallPath

$PACKAGES = @{
    "psw" = @{
        "url" = $IntelPSWURL
        "hash" = $IntelPSWHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_PSW_for_Windows.exe"
    }
    "devcon" = @{
        "url" = $DevconURL
        "hash" = $DevconHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "devcon_package.cab"
    }
    "dcap" = @{
        "url" = $IntelDCAPURL
        "hash" = $IntelDCAPHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_DCAP.exe"
    }
    "azure_dcap_client_nupkg" = @{
        "url" = $AzureDCAPNupkgURL
        "hash" = $AzureDCAPNupkgHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Microsoft.Azure.DCAP.nupkg"
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
        $downloaded_hash = Get-FileHash $PACKAGES[$pkg]["local_file"]
        $expected_hash = $PACKAGES[$pkg]["hash"]
        if ($expected_hash -ne "")
        {
            if ($downloaded_hash.Hash -ne $expected_hash)
            {
                Throw "Error: Computed hash ($downloaded_hash) does not match expected hash ($expected_hash)"
            }
            else
            {
                Write-Output "Computed hash ($downloaded_hash) matches expected hash ($expected_hash)"
            }
        }
    }
    Write-Output "Finished downloading all the packages"
}

function Get-WindowsRelease {
    $releases = @{
        18363 = "Win10"
        18362 = "Win10"
        17763 = "WinServer2019"
        14393 = "WinServer2016"
    }
    $osBuild = [System.Environment]::OSVersion.Version.Build
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $releaseName = $releases[$osBuild]
    # ProductType: 1 - Work Station, 3 - Server
    if (($osBuild -eq 17763) -and ($osInfo.ProductType -eq 1)) {
        $releaseName = "Win10"
    }
    if (!$releaseName) {
        Throw "Cannot find the Windows release name"
    }
    return $releaseName
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
    Write-Output "Installing $InstallerPath with " @parameters
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

function Install-PSW {

    $OS_VERSION = Get-WindowsRelease
    $tempInstallDir = "$PACKAGES_DIRECTORY\Intel_SGX_PSW"
    if(Test-Path $tempInstallDir) {
        Remove-Item -Recurse -Force $tempInstallDir
    }
    Install-ZipTool -ZipPath $PACKAGES["psw"]["local_file"] `
                    -InstallDirectory $tempInstallDir
    if ($OS_VERSION -eq "WinServer2016") {
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
    } else {
        $psw_dir = Get-Item "$tempInstallDir\Intel*SGX*\PSW_INF*\"
        pnputil /add-driver $psw_dir\sgx_psw.inf /install
    }
    Start-ExecuteWithRetry -ScriptBlock {
        Start-Service "AESMService" -ErrorAction Stop
    } -RetryMessage "Failed to start AESMService. Retrying"
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


function Install-DCAP-Dependencies {
    Install-Tool -InstallerPath $PACKAGES["dcap"]["local_file"] `
                 -ArgumentList @('/auto', "$PACKAGES_DIRECTORY\Intel_SGX_DCAP")

    $OS_VERSION = Get-WindowsRelease
    if (($LaunchConfiguration -eq "SGX1FLC") -or ($DCAPClientType -eq "Azure"))
    {
        $drivers = @{
            'WinServer2016' = @{
                'sgx_base_dev' = @{
                    'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\base\WindowsServer2016"
                    'location'    = 'root\SgxLCDevice'
                    'description' = 'Intel(R) Software Guard Extensions Launch Configuration Service'
                }
                'sgx_dcap_dev' = @{
                    'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\dcap\WindowsServer2016"
                    'location'    = 'root\SgxLCDevice_DCAP'
                    'description' = 'Intel(R) Software Guard Extensions DCAP Components Device'
                }
            }
            'WinServer2019' = @{
                'sgx_base' = @{
                    'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\base\WindowsServer2019_Windows10"
                    'location'    = 'root\SgxLCDevice'
                    'description' = 'Intel(R) Software Guard Extensions Launch Configuration Service'
                }
                'sgx_dcap' = @{
                    'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\dcap\WindowsServer2019_Windows10"
                    'location'    = 'root\SgxLCDevice_DCAP'
                    'description' = 'Intel(R) Software Guard Extensions DCAP Components Device'
                }
            }
            'Win10' = @{
                'sgx_base' = @{
                    'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\base\WindowsServer2019_Windows10"
                    'location'    = 'root\SgxLCDevice'
                    'description' = 'Intel(R) Software Guard Extensions Launch Configuration Service'
                }
                'sgx_dcap' = @{
                    'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\dcap\WindowsServer2019_Windows10"
                    'location'    = 'root\SgxLCDevice_DCAP'
                    'description' = 'Intel(R) Software Guard Extensions DCAP Components Device'
                }
            }
        }
        $devConBinaryPath = Get-DevconBinary
        foreach($driver in $drivers[${OS_VERSION}].Keys) {
            $path = $drivers[${OS_VERSION}][$driver]['path']
            $inf = Get-Item "$path\$driver.inf"
            if(!$inf) {
                Throw "Cannot find $driver.inf file"
            }
            if($inf.Count -gt 1) {
                $inf
                Throw "Multiple $driver.inf files found"
            }
            if($LaunchConfiguration -eq "SGX1FLC")
            {
                # Check if the driver is already installed and delete it
                $output = & $devConBinaryPath find "$($drivers[${OS_VERSION}][$driver]['location'])"
                if($LASTEXITCODE) {
                    Throw "Failed searching for $driver driver"
                }
                $output | ForEach-Object {
                    if($_.Contains($drivers[${OS_VERSION}][$driver]['description'])) {
                        Write-Output "Removing driver $($drivers[${OS_VERSION}][$driver]['location'])"
                        Remove-DCAPDriver -Name $drivers[${OS_VERSION}][$driver]['location']
                    }
                }
                Write-Output "Installing driver $($drivers[${OS_VERSION}][$driver]['location'])"
                if($OS_VERSION -eq "WinServer2016")
                {
                    $install = & $devConBinaryPath install "$($inf.FullName)" $drivers[${OS_VERSION}][$driver]['location']
                    if($LASTEXITCODE) {
                        Throw "Failed to install $driver driver"
                    }
                } else{
                    $install = & pnputil /add-driver "$($inf.FullName)" /install
                }
                Write-Output $install
            }
        }
    }

    $TEMP_NUGET_DIR = "$PACKAGES_DIRECTORY\Azure_DCAP_Client_nupkg"
    New-Directory -Path $OE_NUGET_DIR -RemoveExisting
    New-Directory -Path $TEMP_NUGET_DIR -RemoveExisting
    $nupkgDir = Get-Item "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel SGX DCAP for Windows *\nuget"
    if(!$nupkgDir) {
        Throw "Cannot find the Intel DCAP nupkg directory"
    }
    if($nupkgDir.Count -gt 1) {
        Throw "Multiple Intel DCAP nuget directories found"
    }
    Copy-Item -Recurse -Force "$nupkgDir\*" $TEMP_NUGET_DIR

    # Note: the ordering of nuget installs below is important to preserve here until the issue with the EnclaveCommonAPI nuget package gets fixed.
    if ($DCAPClientType -eq "Azure")
    {
        & nuget.exe install 'Microsoft.Azure.DCAP' -Version 1.6.0 -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
        if($LASTEXITCODE -ne 0) {
            Throw "Failed to install nuget Microsoft.Azure.DCAP"
        }
        $targetPath = [System.Environment]::SystemDirectory
        Write-Host "Installing Microsoft.Azure.DCAP library to $targetPath"
        pushd "$OE_NUGET_DIR\Microsoft.Azure.DCAP\tools"
        & ".\InstallAzureDCAP.ps1" $targetPath
        if($LASTEXITCODE) {
            Throw "Failed to install Azure DCAP Client"
        }
        popd
    }
    if (($LaunchConfiguration -eq "SGX1FLC") -or ($DCAPClientType -eq "Azure"))
    {
        & nuget.exe install 'DCAP_Components' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
        if($LASTEXITCODE -ne 0) {
            Throw "Failed to install nuget DCAP_Components"
        }
    }
    & nuget.exe install 'EnclaveCommonAPI' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget EnclaveCommonAPI"
    }
    # Check appropriate launch configuration and if running in a container
    if (($LaunchConfiguration -eq "SGX1FLC") -or (${OS_VERSION} -eq "WinServer2019") -and !($env:UserName -eq "ContainerAdministrator") -and ($env:UserDomain -eq "User Manager"))
    {
        # Please refer to Intel's Windows DCAP documentation for this registry setting: https://download.01.org/intel-sgx/dcap-1.2/windows/docs/Intel_SGX_DCAP_Windows_SW_Installation_Guide.pdf
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters" -Name "SGX_Launch_Config_Optin" -Value 1 -PropertyType DWORD -Force
    }
}

function Install-Chocolatey {

    # Set TLS Protocol, choco causes issues on older versions of Windows
    [Net.ServicePointManager]::SecurityProtocol = "tls12"

    $ErrorActionPreference = "Stop"

    # Elevate to administrator if not already in admin mode
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

    # Set directory for installation - Chocolatey does not lock
    # down the directory if not the default
    $InstallDir='C:\ProgramData\chocoportable'
    $env:ChocolateyInstall="$InstallDir"

    # If your PowerShell Execution policy is restrictive, you may
    # not be able to get around that. Try setting your session to
    # Bypass.
    Set-ExecutionPolicy Bypass -Scope Process -Force;

    # All install options - offline, proxy, etc at
    # https://chocolatey.org/install
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function Install-Build-Dependencies {
    
    cinst nuget.commandline -y
    cinst git -y
    cinst openssl -y
    cinst 7zip -y
    cinst llvm --version 7.0 -y
    cinst shellcheck -y
    cinst vcredist2012 -y
    choco install cmake -y
    # Consider upgrading to 2019 at a later date and sync with Anakrish regarding this
    cinst visualstudio2017professional --params "--no-update" -y
    cinst visualstudio2017-workload-vctools --params "
        --add Microsoft.VisualStudio.Component.VC.CMake.Project
        --add Microsoft.VisualStudio.Component.Windows10SDK.17134
        --add Microsoft.VisualStudio.Component.VC.v141.ARM.Spectre
        --add Microsoft.VisualStudio.Component.VC.v141.ARM64.Spectre
        --includeRecommended" -y
    # Pip installation
    #cinst python3 -y
    # Need to explicitly add to PATH here before trying to use
    Add-ToSystemPath -Path $EnvironmentPath
    #cinst pip -y
    # Need to explicitly add to PATH here before trying to use
    Add-ToSystemPath -Path $EnvironmentPath
    #pip install cmake-format
}

function Install-Run-Time-Dependencies {

    if (($LaunchConfiguration -ne "SGX1FLC-NoIntelDrivers") -and ($LaunchConfiguration -ne "SGX1-NoIntelDrivers"))
    {
        Install-PSW
        Install-DCAP-Dependencies
    } elseif($DCAPClientType -eq "Azure") {
        # This has an edge case which is a user uses windows 2019, turns off Windows Update, runs this scripts and has an old PSW
        # and then the latest dcap.. change would require splitting and refactoring the below into seperate functions but there seems
        # to be an issue with EnclaveCommonAPI. Opening https://github.com/openenclave/openenclave/issues/3524 to tracK
        Install-DCAP-Dependencies
    }
}

function Install-Test-Dependencies {
    if ($ImageConfiguration -eq "CICD")
    {
        # Need NSIS to install packages in CICD for verification/validation, contributors can ignore
        cinst nsis -y
    }
}

try {
    Start-LocalPackagesDownload

    Install-Chocolatey
    Install-Build-Dependencies
    Install-Run-Time-Dependencies
    Install-Test-Dependencies

    # The Open Enclave source directory tree might have file paths exceeding
    # the default limit of 260 characters (especially the 3rd party libraries
    # file paths). Unless the git directory location is short (for example
    # `C:\` or `D:\`), there is a high chance that file paths will exceed 260
    # characters, leading to `Filename too long` file system erros. The fix
    # for this is to disable the file path limit via the proper registry key.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
                     -Name LongPathsEnabled `
                     -Value 1
    Add-ToSystemPath -Path $EnvironmentPath
    Write-Output 'Please reboot your computer for the configuration to complete.'
} catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    Exit 1
} finally {
    Remove-Item -Recurse -Force $PACKAGES_DIRECTORY -ErrorAction SilentlyContinue
}
Exit 0
