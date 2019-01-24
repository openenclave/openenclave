# Data
$Leaves = @(
    "nuget\lib\native\v141\sgx\hw\x86\Debug",     # 00
    "nuget\lib\native\v141\sgx\hw\x86\Release",   # 01

    "nuget\lib\native\v141\sgx\hw\x64\Debug",     # 02
    "nuget\lib\native\v141\sgx\hw\x64\Release",   # 03

    "nuget\lib\native\v141\sgx\sim\x86\Debug",    # 04
    "nuget\lib\native\v141\sgx\sim\x86\Release",  # 05

    "nuget\lib\native\v141\sgx\sim\x64\Debug",    # 06
    "nuget\lib\native\v141\sgx\sim\x64\Release",  # 07

    "nuget\lib\native\v141\tz\hw\arm\Debug",      # 08
    "nuget\lib\native\v141\tz\hw\arm\Release",    # 09

    "nuget\lib\native\v141\tz\sim\x86\Debug",     # 10

    "nuget\tools",                                # 11

    "nuget\build\native\include"                  # 12
)

$EnclaveLibraries = @(
    "oeenclave",
    "oesocket_enc",
    "oestdio_enc"
)

$HostLibraries = @(
    "oehost",
    "oesocket_host",
    "oestdio_host"
)

$OPTEESimLibraries = @(
    "oeenclave_opteesim",
    "oehost_opteesim"
)

# Helper Functions
Function Copy-LibsWorker($Libraries, $SourceLeafPath, $DestinationLeafPath)
{
    ForEach ($Library in $Libraries) {
        $SourceFilePath = Join-Path $SourceLeafPath "$Library.lib"
        Copy-Item -Path $SourceFilePath -Destination $DestinationLeafPath

        # TODO: CMake fails to place PDB files next to static libraries for RelWithDebInfo.
        $SourceFilePath = Join-Path $SourceLeafPath "$Library.pdb"
        Copy-Item -Path $SourceFilePath -Destination $DestinationLeafPath -ErrorAction SilentlyContinue
    }
}

Function Copy-Libs(
    $SourceLeafPath,
    $DestinationLeafPath,
    [Switch]$WithEnclaveLibraries,
    [Switch]$WithHostLibraries,
    [Switch]$WithOPTEESimLibraries)
{
    if ($WithEnclaveLibraries) {
        Copy-LibsWorker $EnclaveLibraries  $SourceLeafPath $DestinationLeafPath
    }

    if ($WithHostLibraries) {
        Copy-LibsWorker $HostLibraries     $SourceLeafPath $DestinationLeafPath
    }

    if ($WithOPTEESimLibraries) {
        Copy-LibsWorker $OPTEESimLibraries $SourceLeafPath $DestinationLeafPath
    }
}

# Copy the basic contents of the NuGet package from the source tree.
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\new_platforms\nuget -Destination .

# Create the directory structure for the build contents.
ForEach ($Leaf in $Leaves) {
    New-Item $Leaf -ItemType Directory | Out-Null
}

# Fetch the relevant build artifacts from the build output.

# SGX Hardware
Copy-Libs build\x86\sgx\out\lib\Debug             $Leaves[00] -WithEnclaveLibraries -WithHostLibraries
Copy-Libs build\x86\sgx\out\lib\RelWithDebInfo    $Leaves[01] -WithEnclaveLibraries -WithHostLibraries

Copy-Libs build\x64\sgx\out\lib\Debug             $Leaves[02] -WithEnclaveLibraries -WithHostLibraries
Copy-Libs build\x64\sgx\out\lib\RelWithDebInfo    $Leaves[03] -WithEnclaveLibraries -WithHostLibraries

# SGX Simulation
Copy-Libs build\x86\sgxsim\out\lib\Debug          $Leaves[04] -WithEnclaveLibraries -WithHostLibraries
Copy-Libs build\x86\sgxsim\out\lib\RelWithDebInfo $Leaves[05] -WithEnclaveLibraries -WithHostLibraries

Copy-Libs build\x64\sgxsim\out\lib\Debug          $Leaves[06] -WithEnclaveLibraries -WithHostLibraries
Copy-Libs build\x64\sgxsim\out\lib\RelWithDebInfo $Leaves[07] -WithEnclaveLibraries -WithHostLibraries

# TrustZone Hardware
Copy-Libs build\arm\tz\out\lib\Debug              $Leaves[08] -WithHostLibraries
Copy-Libs build\arm\tz\out\lib\RelWithDebInfo     $Leaves[09] -WithHostLibraries

# TrustZone Simulation
Copy-Libs build\x86\tzsim\out\lib\Debug           $Leaves[10] -WithEnclaveLibraries -WithHostLibraries -WithOPTEESimLibraries

# oeedger8r Tool
Copy-Item build\oeedger8r.exe                     $Leaves[11]

# Copy the headers from the source tree.

# Open Enclave
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\include\openenclave       -Destination $Leaves[12]

# New Platforms
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\new_platforms\include     -Destination $Leaves[12]
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\3rdparty\RIoT\CyReP\cyrep -Destination $Leaves[12]

Rename-Item -Path "$($Leaves[12])\include" -NewName new_platforms
