# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##====================================================================================
##
## This script fires OE build and test for specified build-type
## Default run with no parameters builds with Debug build-type and for SGX1
## platform and will test in Simulator mode.
## Please note that this script does not install any packages needed for build/test.
## Please install all packages necessary for your test before invoking this script.
## For CI runs, the Docker image will contain the necessary packages.
##
##====================================================================================

[CmdletBinding()]
Param
(
    [Switch]$help,
    [Switch]$ADD_WINDOWS_ENCLAVE_TESTS,
    
    # Valid BUILDTYPE values are Debug|Release
    [ValidateSet("Debug", "Release", IgnoreCase = $false)]
    [String]$BUILD_TYPE = "DEBUG",
    [Switch]$BUILD_ENCLAVES,
    [Parameter(Mandatory = $true)][String]$LINUX_BIN_DIR
)

if ($h -or $help) {
     echo "Script to fire OE build and test with specified build-type/test mode" 
     echo " Usage: "
     echo " ./scripts/test-build-config.ps1"
     echo "        -help to Display usage and exit"
     echo "        -add_windows_enclave_tests to add tests for windows enclave"
     echo "        -build_type Debug|Release"
     echo "        -build_enclaves 1"
     echo "        -linux_bin_dir [directory] directory for linux binaries"
     echo " Default is to build for SGX1 platform, Debug Build type & test in"
     echo " simulator mode"
     echo ""
     exit 0
}

$ErrorActionPreference = "Stop"

$VS_PATH = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$VCVARSPATH=(Join-Path (Get-Item -Path ".\").FullName "\vcvars.txt")

echo "linux_bin_dir: $LINUX_BIN_DIR"

echo "BUILD_TYPE = $BUILD_TYPE"

# Delete the build directory if it exists. This allows calling this script iteratively
# for multiple configurations for a platform.
if (Test-Path "./build" -PathType Container) {
    Remove-Item -Path ./build -Recurse -Force
}

mkdir build
cd build

# Invoke vcvars64.bat and write its entire environment to a text file.
cmd.exe /c "call `"$VS_PATH`" && set > $VCVARSPATH"

# Now 'source' this text file into powershell's environment
Get-Content -Path "$VCVARSPATH" | Foreach-Object {
  if ($_ -match "^(.*?)=(.*)$") {
    Set-Content "env:\$($matches[1])" $matches[2]
  }
}

# Add clang binaries to PATH
$env:PATH += ";C:\Program Files\LLVM\bin"

$BUILD_GENERATOR="Visual Studio 15 2017 Win64"
$BUILD_ENCLAVES_FLAG=""
$LINUX_BIN_FLAG="-DLINUX_BIN_DIR=`"$LINUX_BIN_DIR`""

if ($BUILD_ENCLAVES) {
    $BUILD_GENERATOR="NMake Makefiles"
    $BUILD_ENCLAVES_FLAG="-DBUILD_ENCLAVES=1"
    $LINUX_BIN_FLAG=""

    # Currently disable Windows Enclave Tests for BUILD_ENCLAVE builds.
    # This will be enabled in a later PR.
    Remove-Variable ADD_WINDOWS_ENCLAVE_TESTS
}

if ($ADD_WINDOWS_ENCLAVE_TESTS) {
    $ADD_WINDOWS_ENCLAVE_TESTS_FLAG="-DADD_WINDOWS_ENCLAVE_TESTS=1"
}

# Create Build Type parameter
if ($BUILD_TYPE -eq "Release") {
    $BUILD_TYPE_FLAG="-DCMAKE_BUILD_TYPE=Release"
    $CONFIG_FLAG="-p:Configuration=Release"
}
else {
    $BUILD_TYPE_FLAG="-DCMAKE_BUILD_TYPE=Debug"
    $CONFIG_FLAG="-p:Configuration=Debug"
}

& cmake.exe -G $BUILD_GENERATOR $LINUX_BIN_FLAG $BUILD_TYPE_FLAG $ADD_WINDOWS_ENCLAVE_TESTS_FLAG $BUILD_ENCLAVES_FLAG ..

if ($LASTEXITCODE) {
    echo ""
    echo "cmake failed"
    echo ""
    exit 1
}

if ($LASTEXITCODE) {
    echo ""
    echo "Visual Studio failed"
    echo ""
    exit 1
}

# Build
if ($BUILD_ENCLAVES) {
    cmake.exe --build . --config $BUILD_TYPE
} else {
    msbuild .\ALL_BUILD.vcxproj $CONFIG_FLAG
}
if ($LASTEXITCODE) {
    echo ""
    echo "Build failed for $BUILD_TYPE on Windows"
    echo ""
    exit 1
}

ctest.exe -V -C $BUILD_TYPE
if ($LASTEXITCODE) {
    echo ""
    echo "Test failed for $BUILD_TYPE on Windows"
    echo ""
    exit 1
}
