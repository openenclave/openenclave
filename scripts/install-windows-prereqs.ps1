# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# The Hash parameter defaults below are calculated using Get-FileHash with the default SHA256 hashing algorithm
Param(
    [string]$GitURL = 'https://github.com/git-for-windows/git/releases/download/v2.19.1.windows.1/Git-2.19.1-64-bit.exe',
    [string]$GitHash = '5E11205840937DD4DFA4A2A7943D08DA7443FAA41D92CCC5DAFBB4F82E724793',
    [string]$SevenZipURL = 'https://www.7-zip.org/a/7z1806-x64.msi',
    [string]$SevenZipHash = 'F00E1588ED54DDF633D8652EB89D0A8F95BD80CCCFC3EED362D81927BEC05AA5',
    [string]$VSBuildToolsURL = 'https://aka.ms/vs/15/release/vs_buildtools.exe',
    [string]$VSBuildToolsHash = '7D5B0220670BA1C174F0AE1FF2CE87D65A508E66C321431FBD4751F478037E12',
    [string]$OCamlURL = 'https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/ocpwin64-20160113-4.02.1+ocp1-mingw64.zip',
    [string]$OCamlHash = '369F900F7CDA543ABF674520ED6004CC75008E10BEED0D34845E8A42866D0F3A',
    [string]$Clang7URL = 'http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe',
    [string]$Clang7Hash = '672E4C420D6543A8A9F8EC5F1E5F283D88AC2155EF4C57232A399160A02BFF57',
    [string]$IntelPSWURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/15654/Intel%20SGX%20PSW%20for%20Windows%20v2.4.100.51291.exe',
    [string]$IntelPSWHash = '79AE32E984B5511CE4BF7568403333F837FBCE7E8D5730271C5D68F55BBF251D',
    [string]$ShellCheckURL = 'https://shellcheck.storage.googleapis.com/shellcheck-v0.7.0.zip',
    [string]$ShellCheckHash = '02CFA14220C8154BB7C97909E80E74D3A7FE2CBB7D80AC32ADCAC7988A95E387',
    [string]$NugetURL = 'https://www.nuget.org/api/v2/package/NuGet.exe/3.4.3',
    [string]$NugetHash = '2D4D38666E5C7D27EE487C60C9637BD9DD63795A117F0E0EDC68C55EE6DFB71F',
    [string]$DevconURL = 'https://download.microsoft.com/download/7/D/D/7DD48DE6-8BDA-47C0-854A-539A800FAA90/wdk/Installers/787bee96dbd26371076b37b13c405890.cab',
    [string]$DevconHash = 'A38E409617FC89D0BA1224C31E42AF4344013FEA046D2248E4B9E03F67D5908A',
    [string]$IntelDCAPURL = 'http://registrationcenter-download.intel.com/akdlm/irc_nas/15650/Intel%20SGX%20DCAP%20for%20Windows%20v1.2.100.49925.exe',
    [string]$IntelDCAPHash = 'F31E4451CA32E19CA3DCB0AFC49AFE9F4963C47BF62AAF24A8AE436BDA14FD8B',
    [string]$VCRuntime2012URL = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe',
    [string]$VCRuntime2012Hash = '681BE3E5BA9FD3DA02C09D7E565ADFA078640ED66A0D58583EFAD2C1E3CC4064',
    [string]$AzureDCAPNupkgURL = 'https://www.nuget.org/api/v2/package/Azure.DCAP.Windows/0.0.2',
    [string]$AzureDCAPNupkgHash = 'E319A6C2D136FE5EDB8799305F6151B71F4CE4E67D96CA74538D0AD5D2D793F1',
    [Parameter(mandatory=$true)][string]$InstallPath,
    [Parameter(mandatory=$true)][ValidateSet("SGX1FLC", "SGX1", "SGX1FLC-NoDriver")][string]$LaunchConfiguration,
    [Parameter(mandatory=$true)][ValidateSet("None", "Azure")][string]$DCAPClientType
)

if ($LaunchConfiguration -eq "SGX1")
{
    Write-Host "**** Installing PSW 2.2 ****"

    $IntelPSWURL = "https://oejenkins.blob.core.windows.net/oejenkins/intel_sgx_win_2.2.100.47975_PV.zip"
    $IntelPSWHash = 'EB479D1E029D51E48E534C284FCF5CCA3A937DA43052DCB2F4C71E5F354CA623'
}
else
{
    Write-Host "**** Installing PSW 2.4 ****"
}

$ErrorActionPreference = "Stop"

$PACKAGES_DIRECTORY = Join-Path $env:TEMP "packages"
$OE_NUGET_DIR = Join-Path $InstallPath "prereqs\nuget"

$PACKAGES = @{
    "git" = @{
        "url" = $GitURL
        "hash" = $GitHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Git-64-bit.exe"
    }
    "7z" = @{
        "url" = $SevenZipURL
        "hash" = $SevenZipHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "7z-x64.msi"
    }
    "vs_buildtools" = @{
        "url" = $VSBuildToolsURL
        "hash" = $VSBuildToolsHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "vs_buildtools.exe"
    }
    "ocaml" = @{
        "url" = $OCamlURL
        "hash" = $OCamlHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "ocpwin64.zip"
    }
    "clang7" = @{
        "url" = $Clang7URL
        "hash" = $Clang7Hash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "LLVM-win64.exe"
    }
    "psw" = @{
        "url" = $IntelPSWURL
        "hash" = $IntelPSWHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_PSW_for_Windows.exe"
    }
    "shellcheck" = @{
        "url" = $ShellCheckURL
        "hash" = $ShellCheckHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "shellcheck.zip"
    }
    "nuget" = @{
        "url" = $NugetURL
        "hash" = $NugetHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "nuget.zip"
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
    "vc_runtime_2012" = @{
        "url" = $VCRuntime2012URL
        "hash" = $VCRuntime2012Hash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "vcredist_x64.exe"
    }
    "azure_dcap_client_nupkg" = @{
        "url" = $AzureDCAPNupkgURL
        "hash" = $AzureDCAPNupkgHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Azure.DCAP.Windows.nupkg"
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
        if ($downloaded_hash.Hash -ne $expected_hash)
        {
            Throw "Error: Computed hash ($downloaded_hash) does not match expected hash ($expected_hash)"
        }
        else
        {
            Write-Output "Computed hash ($downloaded_hash) matches expected hash ($expected_hash)"
        }
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

function Install-Nuget {
    $tempInstallDir = "$PACKAGES_DIRECTORY\nuget"
    if(Test-Path -Path $tempInstallDir) {
        Remove-Item -Path $tempInstallDir -Force -Recurse
    }
    Install-ZipTool -ZipPath $PACKAGES["nuget"]["local_file"] `
                    -InstallDirectory $tempInstallDir `
                    -EnvironmentPath @("$tempInstallDir")
    Copy-Item -Force "$tempInstallDir\build\native\Nuget.exe" $PACKAGES_DIRECTORY
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
    $installDir = Join-Path $env:ProgramFiles "shellcheck"
    if(Test-Path -Path $installDir) {
        Remove-Item -Path $installDir -Force -Recurse
    }
    Install-ZipTool -ZipPath $PACKAGES["shellcheck"]["local_file"] `
                    -InstallDirectory $installDir `
                    -EnvironmentPath @("$installDir")
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


function Install-DCAP-Dependencies {
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
        if ($LaunchConfiguration -eq "SGX1FLC")
        {
            Write-Output "Installing driver $($drivers[$driver]['location'])"
            $install = & $devConBinaryPath install "$($inf.FullName)" $drivers[$driver]['location']
            if($LASTEXITCODE) {
                Throw "Failed to install $driver driver"
            }
            Write-Output $install
        }
        elseif ($LaunchConfiguration -eq "SGX1FLC-NoDriver")
        {
            Write-Output "Copying Intel_SGX_DCAP dll files into $($env:SystemRoot)\system32"
            Copy-item -Path $PACKAGES_DIRECTORY\Intel_SGX_DCAP\$driver\drivers\*\*.dll $env:SystemRoot\system32\
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
        & "$PACKAGES_DIRECTORY\nuget.exe" install 'Azure.DCAP.Windows' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
        if($LASTEXITCODE -ne 0) {
            Throw "Failed to install nuget EnclaveCommonAPI"
        }
    }
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'DCAP_Components' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget DCAP_Components"
    }
    & "$PACKAGES_DIRECTORY\nuget.exe" install 'EnclaveCommonAPI' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget EnclaveCommonAPI"
    }

    if ($LaunchConfiguration -eq "SGX1FLC")
    {
        # Please refer to Intel's Windows DCAP documentation for this registry setting: https://download.01.org/intel-sgx/dcap-1.2/windows/docs/Intel_SGX_DCAP_Windows_SW_Installation_Guide.pdf
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters" -Name "SGX_Launch_Config_Optin" -Value 1 -PropertyType DWORD -Force
    }
}

function Install-VCRuntime {
    Write-Log "Installing VC 2012 runtime"
    $p = Start-Process -Wait -PassThru -FilePath $PACKAGES["vc_runtime_2012"]["local_file"] -ArgumentList @("/install", "/passive")
    if($p.ExitCode -ne 0) {
        Throw ("Failed to install VC 2012 runtime. Exit code: {0}" -f $p.ExitCode)
    }
}

function Install-AzureDCAPWindows {
    Write-Log "Installing Azure.DCAP.Windows"
    Write-Host "Installing Azure.DCAP.Windows"

    Copy-Item $PACKAGES['azure_dcap_client_nupkg']['local_file'] -Destination $TEMP_NUGET_DIR -Force

    & "$PACKAGES_DIRECTORY\nuget.exe" install 'Azure.DCAP.Windows' -Source "$TEMP_NUGET_DIR;nuget.org" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
    if($LASTEXITCODE -ne 0) {
        Throw "Failed to install nuget Azure.DCAP.Windows"
    }

    $targetPath = [System.Environment]::SystemDirectory
    Write-Host "Installing Azure.DCAP.Windows library to $targetPath"
    pushd "$OE_NUGET_DIR\Azure.DCAP.Windows\script"
    & ".\InstallAzureDCAP.ps1" $targetPath
    popd
}

try {
    Start-LocalPackagesDownload

    Install-7Zip
    Install-Nuget
    Install-VisualStudio
    Install-LLVM
    Install-Git
    Install-OCaml
    Install-Shellcheck

    if ($LaunchConfiguration -ne "SGX1FLC-NoDriver")
    {
        Install-PSW
    }
    
    if ($DCAPClientType -eq "Azure")
    {
        Write-Host "*** Installing Azure.DCAP.Windows ***"
        Install-AzureDCAPWindows 
    }
    else
    {
        Write-Host "*** Not installing a DCAP Client ***"
    }

    if ( ($LaunchConfiguration -eq "SGX1FLC") -or ($LaunchConfiguration -eq "SGX1FLC-NoDriver") -or ($DCAPClientType -eq "Azure") )
    {
        Install-DCAP-Dependencies
    }

    Install-VCRuntime

    Write-Output 'Please reboot your computer for the configuration to complete.'
} catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    Exit 1
} finally {
    Remove-Item -Recurse -Force $PACKAGES_DIRECTORY -ErrorAction SilentlyContinue
}
Exit 0
