# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# The Hash parameter defaults below are calculated using Get-FileHash with the default SHA256 hashing algorithm
Param(
    [string]$GitURL = 'https://github.com/git-for-windows/git/releases/download/v2.41.0.windows.1/Git-2.41.0-64-bit.exe',
    [string]$GitHash = '45DC30410916B8EC5501BE39D01D5B60535731C04FA68283B4F9DF4920877D4E',
    [string]$OpenSSLURL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/openssl.1.1.1579.74.nupkg',
    [string]$OpenSSLHash = '82678FC7C71CBACA420BC869A1938BC80F2876148A5870D46B4C9A746F6BCEB6',
    [string]$SevenZipURL = 'https://www.7-zip.org/a/7z2301-x64.msi',
    [string]$SevenZipHash = '0BA639B6DACDF573D847C911BD147C6384381A54DAC082B1E8C77BC73D58958B',
    # We skip the hash check for the vs_buildtools.exe file because it is regularly updated without a change to the URL, unfortunately.
    [string]$VSBuildToolsURL = 'https://aka.ms/vs/16/release/vs_buildtools.exe',
    [string]$VSBuildToolsHash = '',
    [string]$ClangURL = 'https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/LLVM-11.1.0-win64.exe',
    [string]$ClangHash = 'B5770BBFAC712D273938CD155E232AFAA85C2E8D865C7CA504A104A838568516',
    [string]$ShellCheckURL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/shellcheck-v0.7.0.zip',
    [string]$ShellCheckHash = '02CFA14220C8154BB7C97909E80E74D3A7FE2CBB7D80AC32ADCAC7988A95E387',
    [string]$Nuget3URL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/nuget.exe.3.4.3.nupkg',
    [string]$Nuget3Hash = '2D4D38666E5C7D27EE487C60C9637BD9DD63795A117F0E0EDC68C55EE6DFB71F',
    [string]$Nuget6URL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/nuget6.exe',
    [string]$Nuget6Hash = 'F2B2145244A3FE1E905599CFB3ADE38E3FCE0C00E73532BDE164EE4F8C8EDCEA',
    [string]$DevconURL = 'https://download.microsoft.com/download/7/D/D/7DD48DE6-8BDA-47C0-854A-539A800FAA90/wdk/Installers/787bee96dbd26371076b37b13c405890.cab',
    [string]$DevconHash = 'A38E409617FC89D0BA1224C31E42AF4344013FEA046D2248E4B9E03F67D5908A',
    # Intel PSW 2.23.100.3 is included in DCAP 1.21.100.3
    [string]$IntelDCAPURL = 'https://downloadmirror.intel.com/834564/Intel_SGX_DCAP_for_Windows_v1.22.100.3.zip',
    [string]$IntelDCAPHash = 'E65061221BF22C1C52E0AF9F610CE53288AA34543A0E152DA2FE755B7079EB93',
    [string]$VCRuntime2012URL = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe',
    [string]$VCRuntime2012Hash = '681BE3E5BA9FD3DA02C09D7E565ADFA078640ED66A0D58583EFAD2C1E3CC4064',
    [string]$AzureDCAPNupkgURL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/microsoft.azure.dcap.1.12.3.nupkg',
    [string]$AzureDCAPNupkgHash = 'A15957E6563418D15DA1585BEB92E6F59B1FB599268FA228306389973FBBF92F',
    [string]$Python3ZipURL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/python-3.7.4-embed-amd64.zip',
    [string]$Python3ZipHash = 'FB65E5CD595AD01049F73B47BC0EE23FD03F0CBADC56CB318990CEE83B37761B',
    [string]$NSISURL = 'https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/nsis-3.05-setup.exe',
    [string]$NSISHash = '1A3CC9401667547B9B9327A177B13485F7C59C2303D4B6183E7BC9E6C8D6BFDB',
    [string]$GetPipURL = 'https://bootstrap.pypa.io/pip/3.4/get-pip.py',
    [string]$GetPipHash = 'DBD5DAE3D1E7F6DF844D630CDF65E0F0D98E483C9997DAEA17C7C9D86F7B38AD',
    [Parameter(mandatory=$true)][string]$InstallPath,
    # SGX1 and SGX1-NoIntelDrivers will be deprecated.
    [Parameter(mandatory=$true)][ValidateSet("SGX1FLC", "SGX1", "SGX1FLC-NoIntelDrivers", "SGX1-NoIntelDrivers")][string]$LaunchConfiguration,
    [Parameter(mandatory=$true)][ValidateSet("None", "Azure")][string]$DCAPClientType,
    [Parameter(mandatory=$false)][switch]$InstallDocker=$false,
    [Parameter(mandatory=$false)][switch]$SkipVSInstall=$false,
    [Parameter(mandatory=$false)][switch]$VerificationOnly=$false
)

$ErrorActionPreference = "Stop"

$PACKAGES_DIRECTORY = Join-Path $env:TEMP "packages"
$OE_NUGET_DIR = $InstallPath

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
    "clang" = @{
        "url" = $ClangURL
        "hash" = $ClangHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "LLVM-win64.exe"
    }
    "shellcheck" = @{
        "url" = $ShellCheckURL
        "hash" = $ShellCheckHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "shellcheck.zip"
    }
    "nuget3" = @{
        "url" = $Nuget3URL
        "hash" = $Nuget3Hash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "nuget3.zip"
    }
    "nuget6" = @{
        "url" = $Nuget6URL
        "hash" = $Nuget6Hash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "nuget6.exe"
    }
    "devcon" = @{
        "url" = $DevconURL
        "hash" = $DevconHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "devcon_package.cab"
    }
    "dcap" = @{
        "url" = $IntelDCAPURL
        "hash" = $IntelDCAPHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Intel_SGX_DCAP.zip"
    }
    "vc_runtime_2012" = @{
        "url" = $VCRuntime2012URL
        "hash" = $VCRuntime2012Hash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "vcredist_x64.exe"
    }
    "azure_dcap_client_nupkg" = @{
        "url" = $AzureDCAPNupkgURL
        "hash" = $AzureDCAPNupkgHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Microsoft.Azure.DCAP.nupkg"
    }
    "openssl" = @{
        "url" = $OpenSSLURL
        "hash" = $OpenSSLHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "openssl.nupkg"
    }
    "python3" = @{
        "url" = $Python3ZipURL
        "hash" = $Python3ZipHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "Python3.zip"
    }
    "get-pip" = @{
        "url" = $GetPipURL
        "hash" = $GetPipHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "get-pip.py"
    }
    "nsis" = @{
        "url" = $NSISURL
        "hash" = $NSISHash
        "local_file" = Join-Path $PACKAGES_DIRECTORY "nsis-3.05-setup.exe"
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
        $wc.Headers.Add("user-agent", "curl");
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
    Param(
        [Parameter(Mandatory=$true)][string]$Version
    )
    $downloadedFile = $PACKAGES["nuget$Version"]["local_file"]
    $installDir = Join-Path $env:ProgramFiles "nuget$version"
    New-Directory -Path $installDir -RemoveExisting
    if ($downloadedFile -match "\.zip$") {
        $tempInstallDir = "$PACKAGES_DIRECTORY\nuget$Version"
        if(Test-Path -Path $tempInstallDir) {
            Remove-Item -Path $tempInstallDir -Force -Recurse
        }
        Install-ZipTool -ZipPath $PACKAGES["nuget$Version"]["local_file"] `
                        -InstallDirectory $tempInstallDir `
                        -EnvironmentPath @("$tempInstallDir")
        Move-Item -Path "$tempInstallDir\build\native\Nuget.exe" -Destination $installDir
        Install-Tool -InstallerPath $PACKAGES["nuget$Version"]["local_file"] `
                    -InstallDirectory $env:ProgramFiles `
                    -ArgumentList @("/install", "/passive") `
                    -EnvironmentPath @("$env:ProgramFiles\NuGet")
    } elseif ($downloadedFile -match "\.exe$") {
        Move-Item -Path $downloadedFile -Destination $installDir
    }
    Add-ToSystemPath -Path $installDir
}
function Install-Python3 {
    $tempInstallDir = "$PACKAGES_DIRECTORY\python3"
    if(Test-Path -Path $tempInstallDir) {
        Remove-Item -Path $tempInstallDir -Force -Recurse
    }
    Install-ZipTool -ZipPath $PACKAGES["python3"]["local_file"] `
                    -InstallDirectory $tempInstallDir `
                    -EnvironmentPath @("$tempInstallDir")

    $installDir = Join-Path $env:ProgramFiles "python-3.7.4"
    New-Directory -Path $installDir -RemoveExisting
    Move-Item -Path "$tempInstallDir\*" -Destination $installDir
    Add-ToSystemPath -Path $installDir

    Start-ExecuteWithRetry -ScriptBlock {
        # Install PIP
        python $PACKAGES["get-pip"]["local_file"]
        $Scripts = Join-Path $installDir "Scripts"
        Add-ToSystemPath -Path $Scripts

        # Enable site packages so that PIP will run, by uncommenting out 'import site'
        $configFile = Join-Path $installdir "python37._pth"
        Set-Content -Path $configFile -Value "python37.zip`n.`n`nimport site"
    } -MaxRetryCount $RetryCount -RetryInterval 3 -RetryMessage "Failed to install PIP. Retrying"

    Start-ExecuteWithRetry -ScriptBlock {
        pip install cmake_format
    } -RetryMessage "Failed to install cmake_format. Retrying"
}

function Install-Git {
    $installDir = Join-Path $env:ProgramFiles "Git"
    Install-Tool -InstallerPath $PACKAGES["git"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/SILENT") `
                 -EnvironmentPath @("$installDir\cmd", "$installDir\bin", "$installDir\mingw64\bin")
}

function Install-OpenSSL {
    $installDir = Join-Path $InstallPath "OpenSSL"
    nuget.exe install openssl -Source $PACKAGES_DIRECTORY -OutputDirectory $InstallPath -ExcludeVersion
    Add-ToSystemPath -Path @("$installDir\bin")
}

function Install-7Zip {
    $installDir = Join-Path $env:ProgramFiles "7-Zip"
    Install-Tool -InstallerPath $PACKAGES["7z"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/quiet", "/passive") `
                 -EnvironmentPath @($installDir)
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
                -EnvironmentPath @("${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build", `
                                   "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\Common7\Tools")
}

# See https://nsis.sourceforge.io/Docs/Chapter3.html#installerusagecommon for valid installer args
function Install-LLVM {
    Install-Tool -InstallerPath $PACKAGES["clang"]["local_file"] `
                 -ArgumentList @("/S", "/D=${env:ProgramFiles}\LLVM") `
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
    $filePath = Join-Path $installDir "shellcheck*.exe"
    $scexe = Get-ChildItem $filePath
    Rename-Item $scexe "shellcheck.exe"
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

# Starting from Intel SGX 2.11.101, the Intel SGX DCAP package contains both DCAP and PSW for Windows Server 2019 and Windows 10.
function Install-DCAP-Dependencies {
    Install-ZipTool -ZipPath $PACKAGES["dcap"]["local_file"] `
                    -InstallDirectory "$PACKAGES_DIRECTORY\Intel_SGX_DCAP"  
    $drivers = @{
        'sgx_base' = @{
            'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\base\WindowsServer2019_Windows10"
            'location'    = 'root\SgxLCDevice'
            'description' = 'Intel(R) Software Guard Extensions Launch Configuration Service'
        }
        'sgx_psw' = @{
            'path'        = "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel*SGX*DCAP*\psw\WindowsServer2019_Windows10"
        }
    }
    foreach($driver in $drivers.Keys) {
        $path = $drivers[$driver]['path']
        $inf = Get-Item "$path\$driver.inf"
        if(!$inf) {
            Throw "Cannot find $driver.inf file"
        }
        if($inf.Count -gt 1) {
            $inf
            Throw "Multiple $driver.inf files found"
        }
        $install = & pnputil /add-driver "$($inf.FullName)" /install
        Write-Output $install
    }
    Start-ExecuteWithRetry -RetryInterval 5 -ScriptBlock {
        Get-Service "AESMService"
    }
    Start-ExecuteWithRetry -ScriptBlock {
        Start-Service -Name "AESMService" -ErrorAction Stop
    }

    $TEMP_NUGET_DIR = "$PACKAGES_DIRECTORY\Azure_DCAP_Client_nupkg"
    New-Directory -Path $OE_NUGET_DIR -RemoveExisting
    New-Directory -Path $TEMP_NUGET_DIR -RemoveExisting
    $nupkgDir = Get-Item "$PACKAGES_DIRECTORY\Intel_SGX_DCAP\Intel_SGX_DCAP_for_Windows_*\nuget"
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
        & nuget.exe install 'Microsoft.Azure.DCAP' -Source "$PACKAGES_DIRECTORY" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
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
        & nuget.exe install 'DCAP_Components' -Source "$TEMP_NUGET_DIR" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
        if($LASTEXITCODE -ne 0) {
            Throw "Failed to install nuget DCAP_Components"
        }
    }
    & nuget.exe install 'EnclaveCommonAPI' -Source "$TEMP_NUGET_DIR" -OutputDirectory "$OE_NUGET_DIR" -ExcludeVersion
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

function Install-NSIS {
    $installDir = Join-Path ${env:ProgramFiles(x86)} "NSIS"

    Install-Tool -InstallerPath $PACKAGES["nsis"]["local_file"] `
                 -InstallDirectory $installDir `
                 -ArgumentList @("/S") `
                 -EnvironmentPath @($installDir, "${installDir}\Bin")
}

function Install-Docker {
    Write-Output '[WARNING] Docker is no longer a prerequisite and installation thereof is deprecated.'
}

try {

    if ($VerificationOnly) {
        Write-Output 'Verification only - Complete'
        Exit 0
    }

    Start-LocalPackagesDownload

    Install-7Zip
    Install-Nuget -Version 3
    Install-Nuget -Version 6
    Install-Python3
    if (!$SkipVSInstall) {
        Install-VisualStudio
    }
    Install-LLVM
    Install-Git
    Install-Shellcheck
    Install-NSIS

    if ($InstallDocker) {
        Install-Docker
    }

    if (($LaunchConfiguration -ne "SGX1FLC-NoIntelDrivers") -and ($LaunchConfiguration -ne "SGX1-NoIntelDrivers") -or ($DCAPClientType -eq "Azure")) {
        Install-DCAP-Dependencies
    }
    # There is a bug with the dcap dependency installation where it will overwrite the installation path folder. 
    # This is a bug in the upstream DCAP package itself. 
    # As we want OpenSSL installed in the same location to be picked up automatically by cmake, just install after dcap installation.
    Install-OpenSSL
    Install-VCRuntime

    # The Open Enclave source directory tree might have file paths exceeding
    # the default limit of 260 characters (especially the 3rd party libraries
    # file paths). Unless the git directory location is short (for example
    # `C:\` or `D:\`), there is a high chance that file paths will exceed 260
    # characters, leading to `Filename too long` file system erros. The fix
    # for this is to disable the file path limit via the proper registry key.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
                     -Name LongPathsEnabled `
                     -Value 1

    Write-Output 'Please reboot your computer for the configuration to complete.'
} catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    Exit 1
} finally {
    Remove-Item -Recurse -Force $PACKAGES_DIRECTORY -ErrorAction SilentlyContinue
}
Exit 0
