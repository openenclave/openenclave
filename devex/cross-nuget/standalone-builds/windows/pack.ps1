# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

Param(
  [string]$SDK_BUILD_PATH = '\source\Build',
  [string]$SDK_PACK_PATH = '\source\Pack'
)

$BUILD_PATH = $SDK_BUILD_PATH.TrimEnd('\')
$PACK_PATH = $SDK_PACK_PATH.TrimEnd('\')
$SDK_DEBUG_BUILD_PATH = "$BUILD_PATH\Default\Debug"
$SDK_RELEASE_BUILD_PATH = "$BUILD_PATH\Default\Release"

$ErrorActionPreference = "Stop"

$LibCopyRules = @(
    New-Object PSObject -Property @{Source="$SDK_DEBUG_BUILD_PATH";Destination="$PACK_PATH\lib\native\win\sgx\default\debug"}
    New-Object PSObject -Property @{Source="$SDK_RELEASE_BUILD_PATH";Destination="$PACK_PATH\lib\native\win\sgx\default\release"}
)

If (Test-Path Pack)
{
    Remove-Item Pack -Recurse -Force
}

Function Get-LibsByGlob([String]$Glob)
{
    Get-ChildItem -Recurse $Glob |
        Where-Object { -Not ($_.FullName.Contains("tests") -or $_.FullName.Contains("tools") -or $_.FullName.Contains("debugger")) }
}

Function Get-EnclaveLibs()
{
    Get-LibsByGlob *.a
}

Function Get-HostLibs()
{
    Get-LibsByGlob *.lib
}

Function Copy-Tools([String]$SgxPlatform)
{
    Push-Location \source\Build\$SgxPlatform\Release\_CPack_Packages\win64\NuGet
    $Bin = (Get-ChildItem -Recurse bin)
    Pop-Location
    Copy-Item -Path "$($Bin.FullName)\*" -Destination $PACK_PATH\tools\win\default -Recurse -Force
}

Function Copy-DebugTools()
{

    $Locations = @(
        New-Object PSObject -Property @{folder="$SDK_DEBUG_BUILD_PATH\host\CMakeFiles\oehost.dir";file="oehost.pdb";destination="$PACK_PATH\lib\native\win\sgx\default\debug\host\msvc-14.16.27023"}
        New-Object PSObject -Property @{folder="$SDK_RELEASE_BUILD_PATH\debugger\debugrt\host";file="oedebugrt.*";destination="$PACK_PATH\tools\win\default"}
    )

    foreach ($location in $Locations) {
        Push-Location $location.folder
        $Bin = (Get-ChildItem -Recurse $location.file | Where { ! $_.FullName.Contains("manifest") } )
        Pop-Location
        foreach ($file in $Bin)
        {
            Copy-Item -Path "$($file.FullName)" -Destination $location.destination -Force
        }
    }

}


Function Copy-Includes([String]$SgxPlatform, [String]$BuildType)
{
    Push-Location \source\Build\$SgxPlatform\$BuildType\_CPack_Packages\win64\NuGet
    $Inc = (Get-ChildItem -Recurse include)
    Pop-Location

    Copy-Item -Path $Inc.FullName -Destination $PACK_PATH\build\native\win\sgx\$SgxPlatform\$BuildType\ -Recurse -Force
}


New-Item -ItemType Directory -Path $PACK_PATH\build\native\win\sgx\default\debug | Out-Null
New-Item -ItemType Directory -Path $PACK_PATH\build\native\win\sgx\default\release | Out-Null

New-Item -ItemType Directory -Path $PACK_PATH\lib\native\win\sgx\default\debug\enclave\clang-8 | Out-Null
New-Item -ItemType Directory -Path $PACK_PATH\lib\native\win\sgx\default\debug\host\msvc-14.16.27023 | Out-Null

New-Item -ItemType Directory -Path $PACK_PATH\lib\native\win\sgx\default\release\enclave\clang-8 | Out-Null
New-Item -ItemType Directory -Path $PACK_PATH\lib\native\win\sgx\default\release\host\msvc-14.16.27023 | Out-Null

New-Item -ItemType Directory -Path $PACK_PATH\tools\win\default | Out-Null


$LibCopyRules | ForEach-Object {
    Push-Location $_.Source
    $EnclaveLibs = Get-EnclaveLibs
    $HostLibs = Get-HostLibs
    Copy-Item -Path $EnclaveLibs -Destination (Join-Path -Path $_.Destination -ChildPath enclave\clang-8)
    Copy-Item -Path $HostLibs -Destination (Join-Path -Path $_.Destination -ChildPath host\msvc-14.16.27023)
    Pop-Location
}

Copy-Includes Default Debug
Copy-Includes Default Release

Copy-Tools Default
Copy-DebugTools
