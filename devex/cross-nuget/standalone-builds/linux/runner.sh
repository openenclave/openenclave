#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

echo "Override OS_CODENAME: $OS_CODENAME, OE_SDK_PATH: $OE_SDK_PATH, OPTEE_BUILD_PATH: $OPTEE_BUILD_PATH, BUILD PATH: $BUILD_PATH"

OS_CODENAME="$OS_CODENAME"
if [ -z "$OS_CODENAME" ]; then
  echo "OS_CODENAME override not given, attempting to find OS"
  OS_CODENAME=$('find /etc/os-release 2>/dev/null && cat /etc/os-release 2>/dev/null | grep UBUNTU_CODENAME | cut -d= -f2')
fi
if [ -z "$OS_CODENAME" ]; then
  echo "OS_CODENAME unavailable"
  exit 1
fi

# OP-TEE Build Output Folders
OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH=$OPTEE_BUILD_PATH/3.6.0/vexpress-qemu_armv8a/debug
OPTEE_DEBUG_GRAPEBOARD_OUT_PATH=$OPTEE_BUILD_PATH/3.6.0/ls-ls1012grapeboard/debug

OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH=$OPTEE_BUILD_PATH/3.6.0/vexpress-qemu_armv8a/release
OPTEE_RELEASE_GRAPEBOARD_OUT_PATH=$OPTEE_BUILD_PATH/3.6.0/ls-ls1012grapeboard/release

mkdir -p "$OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH"
mkdir -p "$OPTEE_DEBUG_GRAPEBOARD_OUT_PATH"
mkdir -p "$OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$OPTEE_RELEASE_GRAPEBOARD_OUT_PATH"

# SDK Build Output (SGX)
SDK_DEBUG_SGX_DEFAULT_OUT_PATH=$BUILD_PATH/$OS_CODENAME/sdk/sgx/default/debug
SDK_RELEASE_SGX_DEFAULT_OUT_PATH=$BUILD_PATH/$OS_CODENAME/sdk/sgx/default/release

mkdir -p "$SDK_DEBUG_SGX_DEFAULT_OUT_PATH"
mkdir -p "$SDK_RELEASE_SGX_DEFAULT_OUT_PATH"

# SDK Build Output (OP-TEE)
SDK_DEBUG_OPTEE_QEMU_ARMV8_OUT_PATH=$BUILD_PATH/$OS_CODENAME/sdk/optee/3.6.0/vexpress-qemu_armv8a/debug
SDK_DEBUG_OPTEE_GRAPEBOARD_OUT_PATH=$BUILD_PATH/$OS_CODENAME/sdk/optee/3.6.0/ls-ls1012grapeboard/debug

SDK_RELEASE_OPTEE_QEMU_ARMV8_OUT_PATH=$BUILD_PATH/$OS_CODENAME/sdk/optee/3.6.0/vexpress-qemu_armv8a/release
SDK_RELEASE_OPTEE_GRAPEBOARD_OUT_PATH=$BUILD_PATH/$OS_CODENAME/sdk/optee/3.6.0/ls-ls1012grapeboard/release

mkdir -p "$SDK_DEBUG_OPTEE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$SDK_DEBUG_OPTEE_GRAPEBOARD_OUT_PATH"
mkdir -p "$SDK_RELEASE_OPTEE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$SDK_RELEASE_OPTEE_GRAPEBOARD_OUT_PATH"

# Source Paths
if [ -z "$OE_SDK_PATH" ]; then
  OE_SDK_PATH="$PWD/sdk"
fi
OPTEE_PATH="$OE_SDK_PATH/3rdparty/optee/optee_os"

echo "Build settings OS_CODENAME: $OS_CODENAME, OE_SDK_PATH: $OE_SDK_PATH, OPTEE_PATH: $OPTEE_PATH, PWD: $PWD OPTEE_BUILD_PATH: $OPTEE_BUILD_PATH, BUILD PATH: $BUILD_PATH"

## ========================================
## Build SDK (SGX)
## ========================================

# Build the SDK for Intel SGX Default Debug
echo "Building: SDK/SGX/Default/Debug" >> runner."$OS_CODENAME"
pushd "$SDK_DEBUG_SGX_DEFAULT_OUT_PATH" || exit 1
cmake -G Ninja "$OE_SDK_PATH"                              \
    -DLVI_MITIGATION=ControlFlow                           \
    -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
    -DCMAKE_BUILD_TYPE=Debug                               \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'         \
    -DCPACK_GENERATOR=DEB || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done

# Build the SDK for Intel SGX Default Release
echo "Building: SDK/SGX/Default/Release" >> runner."$OS_CODENAME"
pushd "$SDK_RELEASE_SGX_DEFAULT_OUT_PATH" || exit 1
cmake -G Ninja "$OE_SDK_PATH"                              \
    -DLVI_MITIGATION=ControlFlow                           \
    -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin  \
    -DCMAKE_BUILD_TYPE=Release                             \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'         \
    -DCPACK_GENERATOR=DEB || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done

## ========================================
## Build SDK (OP-TEE)
## ========================================

# Build the SDK for OP-TEE on QEMU ARMv8 Debug
echo "Building: SDK/OP-TEE/QEMU/Debug" >> runner."$OS_CODENAME"
pushd "$SDK_DEBUG_OPTEE_QEMU_ARMV8_OUT_PATH" || exit 1
DEV_KIT="$OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH"
cmake -G Ninja "$OE_SDK_PATH"                                  \
    -DCMAKE_BUILD_TYPE=Debug                                   \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'             \
    -DCPACK_GENERATOR=DEB                                      \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake\
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done

# Build the SDK for OP-TEE on the Scalys Grapeboard Debug
echo "Building: SDK/OP-TEE/Grapeboard/Debug" >> runner."$OS_CODENAME"
pushd "$SDK_DEBUG_OPTEE_GRAPEBOARD_OUT_PATH" || exit 1
DEV_KIT="$OPTEE_DEBUG_GRAPEBOARD_OUT_PATH"
cmake -G Ninja "$OE_SDK_PATH"                                  \
    -DCMAKE_BUILD_TYPE=Debug                                   \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'             \
    -DCPACK_GENERATOR=DEB                                      \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake\
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done

# Build the SDK for OP-TEE on QEMU ARMv8 Release
echo "Building: SDK/OP-TEE/QEMU/Release" >> runner."$OS_CODENAME"
pushd "$SDK_RELEASE_OPTEE_QEMU_ARMV8_OUT_PATH" || exit 1
DEV_KIT="$OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH"
cmake -G Ninja "$OE_SDK_PATH"                                  \
    -DCMAKE_BUILD_TYPE=Release                                 \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'             \
    -DCPACK_GENERATOR=DEB                                      \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake\
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done

# Build the SDK for OP-TEE on the Scalys Grapeboard Release
echo "Building: SDK/OP-TEE/Grapeboard/Release" >> runner."$OS_CODENAME"
pushd "$SDK_RELEASE_OPTEE_GRAPEBOARD_OUT_PATH" || exit 1
DEV_KIT="$OPTEE_RELEASE_GRAPEBOARD_OUT_PATH"
cmake -G Ninja "$OE_SDK_PATH"                                  \
    -DCMAKE_BUILD_TYPE=Release                                 \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'             \
    -DCPACK_GENERATOR=DEB                                      \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake\
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done
