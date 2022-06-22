# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

$ErrorActionPreference = "Stop"

$LibCopyRules = @(
    New-Object PSObject -Property @{Source="$PWD\Build\Default\Debug";Destination="$PWD\Pack\lib\native\win\sgx\default\debug"}
    New-Object PSObject -Property @{Source="$PWD\Build\Default\Release";Destination="$PWD\Pack\lib\native\win\sgx\default\release"}
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
    Push-Location $PWD\Build\$SgxPlatform\Release\_CPack_Packages\win64\NuGet
    $Bin = (Get-ChildItem -Recurse bin)
    Pop-Location
    Copy-Item -Path "$($Bin.FullName)\*" -Destination .\Pack\tools\win\default -Recurse -Force
}

Function Copy-DebugTools()
{

    $Locations = @(
        New-Object PSObject -Property @{folder="$PWD\Build\Default\Debug\host\CMakeFiles\oehost.dir";file="oehost.pdb";destination="$PWD\Pack\lib\native\win\sgx\default\debug\host\msvc-14.16.27023"}
        New-Object PSObject -Property @{folder="$PWD\Build\Default\Release\debugger\debugrt\host";file="oedebugrt.*";destination="$PWD\Pack\tools\win\default"}
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
    Push-Location $PWD\Build\$SgxPlatform\$BuildType\_CPack_Packages\win64\NuGet
    $Inc = (Get-ChildItem -Recurse include)
    Pop-Location

    Copy-Item -Path $Inc.FullName -Destination .\Pack\build\native\win\sgx\$SgxPlatform\$BuildType\ -Recurse -Force
}


New-Item -ItemType Directory -Path Pack\build\native\win\sgx\default\debug | Out-Null
New-Item -ItemType Directory -Path Pack\build\native\win\sgx\default\release | Out-Null

New-Item -ItemType Directory -Path Pack\lib\native\win\sgx\default\debug\enclave\clang-10 | Out-Null
New-Item -ItemType Directory -Path Pack\lib\native\win\sgx\default\debug\host\msvc-14.16.27023 | Out-Null

New-Item -ItemType Directory -Path Pack\lib\native\win\sgx\default\release\enclave\clang-10 | Out-Null
New-Item -ItemType Directory -Path Pack\lib\native\win\sgx\default\release\host\msvc-14.16.27023 | Out-Null

New-Item -ItemType Directory -Path Pack\tools\win\default | Out-Null


$LibCopyRules | ForEach-Object {
    Push-Location $_.Source
    $EnclaveLibs = Get-EnclaveLibs
    $HostLibs = Get-HostLibs
    Copy-Item -Path $EnclaveLibs -Destination (Join-Path -Path $_.Destination -ChildPath enclave\clang-10)
    Copy-Item -Path $HostLibs -Destination (Join-Path -Path $_.Destination -ChildPath host\msvc-14.16.27023)
    Pop-Location
}

Copy-Includes Default Debug
Copy-Includes Default Release

Copy-Tools Default
Copy-DebugTools
