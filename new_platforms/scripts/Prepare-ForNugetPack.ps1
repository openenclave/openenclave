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

$Libraries = @(
    "oeenclave",
    "oehost",
    "oesocket_enc",
    "oesocket_host",
    "oestdio_enc",
    "oestdio_host"
)

$Extensions = @(
    "lib",
    "pdb"
)

# Helper Functions
Function Copy-Libs($SourceLeafPath, $DestinationLeafPath)
{
    ForEach ($Library in $Libraries) {
        ForEach ($Extension in $Extensions) {
            $SourceFilePath = Join-Path $SourceLeafPath "$Library.$Extension"
            Copy-Item -Path $SourceFilePath -Destination $DestinationLeafPath
        }
    }
}

# Create Directory Structure
ForEach ($Leaf in $Leaves) {
    New-Item $Leaf -ItemType Directory
}

# Fetch the basic contents to be included in the NuGet package from the source
# tree.
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\new_platforms\nuget -Destination .\nuget

# Now fetch the build output for each platform/TEE/target combination.

# SGX Hardware
Copy-Libs build\x86\sgx\out\Debug\lib    $Leaves[0]
Copy-Libs build\x64\sgx\out\Debug\lib    $Leaves[1]

# SGX Simulation
Copy-Libs build\x86\sgxsim\out\Debug\lib $Leaves[2]
Copy-Libs build\x64\sgxsim\out\Debug\lib $Leaves[3]

# TrustZone Hardware
Copy-Libs build\arm\tz\out\Debug\lib     $Leaves[4]

# TrustZone Simulation
Copy-Libs build\x86\tzsim\out\Debug\lib  $Leaves[5]

# Finally, copy the headers from the source tree.
Copy-Item -Recurse -Path $ENV:SOURCES_PATH\include\openenclave -Destination $Leaves[6]
