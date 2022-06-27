#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

WORKING_DIR=$1

OS_CODENAME=$('grep UBUNTU_CODENAME /etc/os-release | cut -d= -f2')

cd "$WORKING_DIR" || exit 1

# OP-TEE Build Output Folders
OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH="$PWD/build/optee/3.6.0/vexpress-qemu_armv8a/debug"
OPTEE_DEBUG_GRAPEBOARD_OUT_PATH="$PWD/build/optee/3.6.0/ls-ls1012grapeboard/debug"

OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH="$PWD/build/optee/3.6.0/vexpress-qemu_armv8a/release"
OPTEE_RELEASE_GRAPEBOARD_OUT_PATH="$PWD/build/optee/3.6.0/ls-ls1012grapeboard/release"

mkdir -p "$OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH"
mkdir -p "$OPTEE_DEBUG_GRAPEBOARD_OUT_PATH"
mkdir -p "$OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$OPTEE_RELEASE_GRAPEBOARD_OUT_PATH"

# SDK Build Output (SGX)
SDK_DEBUG_SGX_DEFAULT_OUT_PATH="$PWD/build/$OS_CODENAME/sdk/sgx/default/debug"
SDK_RELEASE_SGX_DEFAULT_OUT_PATH="$PWD/build/$OS_CODENAME/sdk/sgx/default/release"

mkdir -p "$SDK_DEBUG_SGX_DEFAULT_OUT_PATH"
mkdir -p "$SDK_RELEASE_SGX_DEFAULT_OUT_PATH"

# SDK Build Output (OP-TEE)
SDK_DEBUG_OPTEE_QEMU_ARMV8_OUT_PATH="$PWD/build/$OS_CODENAME/sdk/optee/3.6.0/vexpress-qemu_armv8a/debug"
SDK_DEBUG_OPTEE_GRAPEBOARD_OUT_PATH="$PWD/build/$OS_CODENAME/sdk/optee/3.6.0/ls-ls1012grapeboard/debug"

SDK_RELEASE_OPTEE_QEMU_ARMV8_OUT_PATH="$PWD/build/$OS_CODENAME/sdk/optee/3.6.0/vexpress-qemu_armv8a/release"
SDK_RELEASE_OPTEE_GRAPEBOARD_OUT_PATH="$PWD/build/$OS_CODENAME/sdk/optee/3.6.0/ls-ls1012grapeboard/release"

mkdir -p "$SDK_DEBUG_OPTEE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$SDK_DEBUG_OPTEE_GRAPEBOARD_OUT_PATH"
mkdir -p "$SDK_RELEASE_OPTEE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$SDK_RELEASE_OPTEE_GRAPEBOARD_OUT_PATH"

# Source Paths
OE_SDK_PATH="$PWD/sdk"
OPTEE_PATH="$OE_SDK_PATH/3rdparty/optee/optee_os"

## ========================================
## Build OP-TEE
## ========================================

# OP-TEE fails to build on Ubuntu 16.04 (Xenial) due to a bug in the version of
# binutils that ships with that release.
if [[ "$OS_CODENAME" == "bionic" ]]; then
    # OP-TEE Build Debug Flags
    OPTEE_DEBUG_FLAGS=$(cat << EOF
platform-cflags-optimization=-O0
CFG_CRYPTO_SIZE_OPTIMIZATION=y
CFG_PAGED_USER_TA=n
CFG_REE_FS=n
CFG_RPMB_FS=y
CFG_RPMB_TESTKEY=y
CFG_RPMB_WRITE_KEY=n
CFG_RPMB_RESET_FAT=n
CFG_TEE_CORE_DEBUG=y
CFG_WITH_PAGER=n
CFG_UNWIND=n
CFG_TEE_CORE_LOG_LEVEL=2
CFG_TEE_TA_LOG_LEVEL=4
CFG_WITH_USER_TA=y
CFG_GRPC=y
EOF
)

    # OP-TEE Build Release Flags
    OPTEE_RELEASE_FLAGS=$(cat << EOF
platform-cflags-optimization=-Os
CFG_CRYPTO_SIZE_OPTIMIZATION=y
CFG_PAGED_USER_TA=n
CFG_REE_FS=n
CFG_RPMB_FS=y
CFG_RPMB_TESTKEY=y
CFG_RPMB_WRITE_KEY=n
CFG_RPMB_RESET_FAT=n
CFG_TEE_CORE_DEBUG=n
CFG_WITH_PAGER=n
CFG_UNWIND=n
CFG_TEE_CORE_LOG_LEVEL=0
CFG_TEE_TA_LOG_LEVEL=0
CFG_WITH_USER_TA=y
CFG_GRPC=y
EOF
)

    # Cross-compiler Prefixes
    CROSS_COMPILE=aarch64-linux-gnu-
    TA_CROSS_COMPILE=aarch64-linux-gnu-
    TA_CROSS_COMPILE_32=arm-linux-gnueabi-

    if hash ccache 2>/dev/null; then
        CROSS_COMPILE="ccache $CROSS_COMPILE"
        TA_CROSS_COMPILE="ccache $TA_CROSS_COMPILE"
        TA_CROSS_COMPILE_32="ccache $TA_CROSS_COMPILE_32"
    fi

    # Build OP-TEE for QEMU ARMv8 Debug
    echo "Building: OP-TEE/QEMU/Debug" >> runner."$OS_CODENAME"
    pushd "$OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH" || exit 1
    # shellcheck disable=SC2086
    ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"        \
        PLATFORM=vexpress-qemu_armv8a                  \
        O="$PWD"                                       \
        $OPTEE_DEBUG_FLAGS                             \
        CROSS_COMPILE="$CROSS_COMPILE"                 \
        CROSS_COMPILE_core="$CROSS_COMPILE"            \
        CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
        CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
        CFG_ARM64_core=y || exit 1
    popd || exit 1

    # Build OP-TEE for the Scalys Grapeboard Debug
    echo "Building: OP-TEE/Grapeboard/Debug" >> runner."$OS_CODENAME"
    pushd "$OPTEE_DEBUG_GRAPEBOARD_OUT_PATH" || exit 1
    # shellcheck disable=SC2086
    ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"        \
        PLATFORM=ls-ls1012grapeboard                   \
        O="$PWD"                                       \
        $OPTEE_DEBUG_FLAGS                             \
        CROSS_COMPILE="$CROSS_COMPILE"                 \
        CROSS_COMPILE_core="$CROSS_COMPILE"            \
        CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
        CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
        CFG_ARM64_core=y || exit 1
    popd || exit 1

    # Build OP-TEE for QEMU ARMv8 Release
    echo "Building: OP-TEE/QEMU/Release" >> runner."$OS_CODENAME"
    pushd "$OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH" || exit 1
    # shellcheck disable=SC2086
    ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"        \
        PLATFORM=vexpress-qemu_armv8a                  \
        O="$PWD"                                       \
        $OPTEE_RELEASE_FLAGS                           \
        CROSS_COMPILE="$CROSS_COMPILE"                 \
        CROSS_COMPILE_core="$CROSS_COMPILE"            \
        CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
        CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
        CFG_ARM64_core=y || exit 1
    popd || exit 1

    # Build OP-TEE for the Scalys Grapeboard Release
    echo "Building: OP-TEE/Grapeboard/Release" >> runner."$OS_CODENAME"
    pushd "$OPTEE_RELEASE_GRAPEBOARD_OUT_PATH" || exit 1
    # shellcheck disable=SC2086
    ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"        \
        PLATFORM=ls-ls1012grapeboard                   \
        O="$PWD"                                       \
        $OPTEE_RELEASE_FLAGS                           \
        CROSS_COMPILE="$CROSS_COMPILE"                 \
        CROSS_COMPILE_core="$CROSS_COMPILE"            \
        CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
        CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
        CFG_ARM64_core=y || exit 1
    popd || exit 1

    # Clear OP-TEE build variables
    unset OPTEE_DEBUG_FLAGS
    unset OPTEE_RELEASE_FLAGS
    unset CROSS_COMPILE
    unset TA_CROSS_COMPILE
    unset TA_CROSS_COMPILE_32
fi

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
cmake -G Ninja "$OE_SDK_PATH"                                    \
    -DCMAKE_BUILD_TYPE=Debug                                     \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'               \
    -DCPACK_GENERATOR=DEB                                        \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake  \
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
cmake -G Ninja "$OE_SDK_PATH"                                    \
    -DCMAKE_BUILD_TYPE=Debug                                     \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'               \
    -DCPACK_GENERATOR=DEB                                        \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake  \
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
cmake -G Ninja "$OE_SDK_PATH"                                    \
    -DCMAKE_BUILD_TYPE=Release                                   \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'               \
    -DCPACK_GENERATOR=DEB                                        \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake  \
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
cmake -G Ninja "$OE_SDK_PATH"                                    \
    -DCMAKE_BUILD_TYPE=Release                                   \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'               \
    -DCPACK_GENERATOR=DEB                                        \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake  \
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit 1
ninja package || exit 1

mkdir expand
pushd expand || exit 1
7z x ../*.deb || exit 1
tar xf data.tar || exit 1
popd || exit 1
popd || exit 1  # SDK Build Done
