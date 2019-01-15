# Data
$Leaves = @(
    "nuget\lib\native\v141\sgx\hw\x86\Debug",
    "nuget\lib\native\v141\sgx\hw\x64\Debug",

    "nuget\lib\native\v141\sgx\sim\x86\Debug",
    "nuget\lib\native\v141\sgx\sim\x64\Debug",

    "nuget\lib\native\v141\tz\hw\arm\Debug",
    "nuget\lib\native\v141\tz\sim\x86\Debug",

    "nuget\build\native\include"
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

$Extensions = @(
    "lib",
    "pdb"
)

# Helper Functions
Function Copy-LibsWorker($Libraries, $SourceLeafPath, $DestinationLeafPath)
{
    ForEach ($Library in $Libraries) {
        ForEach ($Extension in $Extensions) {
            $SourceFilePath = Join-Path $SourceLeafPath "$Library.$Extension"
            Copy-Item -Path $SourceFilePath -Destination $DestinationLeafPath
        }
    }
}

Function Copy-Libs($SourceLeafPath, $DestinationLeafPath, [Switch]$WithEnclaveLibraries, [Switch]$WithHostLibraries)
{
    if ($WithEnclaveLibraries) {
        Copy-LibsWorker $EnclaveLibraries $SourceLeafPath $DestinationLeafPath
    }

    if ($WithHostLibraries) {
        Copy-LibsWorker $HostLibraries $SourceLeafPath $DestinationLeafPath
    }
}

# Create Directory Structure
ForEach ($Leaf in $Leaves) {
    New-Item $Leaf -ItemType Directory | Out-Null
}

# Fetch the basic contents to be included in the NuGet package from the source
# tree.
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\new_platforms\nuget -Destination .\nuget

# Now fetch the build output for each platform/TEE/target combination.

# SGX Hardware
Copy-Libs build\x86\sgx\out\lib\Debug    $Leaves[0] -WithEnclaveLibraries -WithHostLibraries
Copy-Libs build\x64\sgx\out\lib\Debug    $Leaves[1] -WithEnclaveLibraries -WithHostLibraries

# SGX Simulation
Copy-Libs build\x86\sgxsim\out\lib\Debug $Leaves[2] -WithEnclaveLibraries -WithHostLibraries
Copy-Libs build\x64\sgxsim\out\lib\Debug $Leaves[3] -WithEnclaveLibraries -WithHostLibraries

# TrustZone Hardware
Copy-Libs build\arm\tz\out\lib\Debug     $Leaves[4] -WithHostLibraries

# TrustZone Simulation
Copy-Libs build\x86\tzsim\out\lib\Debug  $Leaves[5] -WithEnclaveLibraries -WithHostLibraries

# Finally, copy the headers from the source tree.
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\include\openenclave -Destination $Leaves[6]
