# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Build for SGX
# |- Default (with LVI)
#    |- Debug
#    |- Release

Param(
  [string]$SDK_PATH = 'SDK',
  [string]$SDK_TAG = 'master',
  [string]$SDK_BUILD_PATH = '\source\Build'
)

$BUILD_PATH = $SDK_BUILD_PATH.TrimEnd('\')
$SDK_DEBUG_BUILD_PATH = "$BUILD_PATH\Default\Debug"
$SDK_RELEASE_BUILD_PATH = "$BUILD_PATH\Default\Release"

$ErrorActionPreference = "Stop"

If (-not (Test-Path -Path $SDK_PATH))
{
    git clone --recursive --depth=1 https://github.com/openenclave/openenclave SDK -b $OE_SDK_TAG
    $SDK_PATH = (Join-Path -Path $PWD -ChildPath SDK)
}
Else
{
    $SDK_PATH = (Convert-Path $SDK_PATH)
}

If (Test-Path Build)
{
    Remove-Item Build -Recurse -Force
}

New-Item -ItemType Directory -Path $SDK_RELEASE_BUILD_PATH | Out-Null
New-Item -ItemType Directory -Path $SDK_DEBUG_BUILD_PATH | Out-Null

Push-Location -Path $SDK_DEBUG_BUILD_PATH
cmake $SDK_PATH -G Ninja -DLVI_MITIGATION=ControlFlow -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DBUILD_ENCLAVES=ON -DCPACK_GENERATOR=NuGet -DCMAKE_BUILD_TYPE=Debug
ninja
cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
cpack.exe
Pop-Location

Push-Location -Path $SDK_RELEASE_BUILD_PATH
cmake $SDK_PATH -G Ninja -DLVI_MITIGATION=ControlFlow -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DBUILD_ENCLAVES=ON -DCPACK_GENERATOR=NuGet -DCMAKE_BUILD_TYPE=Release
ninja
cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
cpack.exe
Pop-Location
