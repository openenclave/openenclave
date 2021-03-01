#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set +x

OPTEE_PATH=${OE_SDK_PATH}/3rdparty/optee/optee_os

echo "Override OE_SDK_PATH: $OE_SDK_PATH, OPTEE_PATH: $OPTEE_PATH, OPTEE_BUILD_PATH: $OPTEE_BUILD_PATH"


# OP-TEE Build Output Folders
OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH=${OPTEE_BUILD_PATH}/3.6.0/vexpress-qemu_armv8a/debug
OPTEE_DEBUG_GRAPEBOARD_OUT_PATH=${OPTEE_BUILD_PATH}/3.6.0/ls-ls1012grapeboard/debug

OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH=${OPTEE_BUILD_PATH}/3.6.0/vexpress-qemu_armv8a/release
OPTEE_RELEASE_GRAPEBOARD_OUT_PATH=${OPTEE_BUILD_PATH}/3.6.0/ls-ls1012grapeboard/release

# Create OP-TEE build directories
mkdir -p "$OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH"
mkdir -p "$OPTEE_DEBUG_GRAPEBOARD_OUT_PATH"
mkdir -p "$OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH"
mkdir -p "$OPTEE_RELEASE_GRAPEBOARD_OUT_PATH"

## ========================================
## Build OP-TEE
## ========================================

# OP-TEE fails to build on Ubuntu 16.04 (Xenial) due to a bug in the version of
# binutils that ships with that release.
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
echo "Building: OP-TEE/QEMU/Debug"
cd "$OPTEE_DEBUG_QEMU_ARMV8_OUT_PATH" || exit 1
ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"      \
  PLATFORM=vexpress-qemu_armv8a                  \
  O="$PWD"                                       \
  $OPTEE_DEBUG_FLAGS                             \
  CROSS_COMPILE="$CROSS_COMPILE"                 \
  CROSS_COMPILE_core="$CROSS_COMPILE"            \
  CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
  CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
  CFG_ARM64_core=y || exit 1

# Build OP-TEE for the Scalys Grapeboard Debug
echo "Building: OP-TEE/Grapeboard/Debug"
cd "$OPTEE_DEBUG_GRAPEBOARD_OUT_PATH" || exit 1
ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"      \
  PLATFORM=ls-ls1012grapeboard                   \
  O="$PWD"                                       \
  $OPTEE_DEBUG_FLAGS                             \
  CROSS_COMPILE="$CROSS_COMPILE"                 \
  CROSS_COMPILE_core="$CROSS_COMPILE"            \
  CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
  CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
  CFG_ARM64_core=y || exit 1

# Build OP-TEE for QEMU ARMv8 Release
echo "Building: OP-TEE/QEMU/Release"
cd "$OPTEE_RELEASE_QEMU_ARMV8_OUT_PATH" || exit 1
ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"      \
  PLATFORM=vexpress-qemu_armv8a                  \
  O="$PWD"                                       \
  $OPTEE_RELEASE_FLAGS                           \
  CROSS_COMPILE="$CROSS_COMPILE"                 \
  CROSS_COMPILE_core="$CROSS_COMPILE"            \
  CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
  CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
  CFG_ARM64_core=y || exit 1

# Build OP-TEE for the Scalys Grapeboard Release
echo "Building: OP-TEE/Grapeboard/Release"
cd "$OPTEE_RELEASE_GRAPEBOARD_OUT_PATH" || exit 1
ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"      \
  PLATFORM=ls-ls1012grapeboard                   \
  O="$PWD"                                       \
  $OPTEE_RELEASE_FLAGS                           \
  CROSS_COMPILE="$CROSS_COMPILE"                 \
  CROSS_COMPILE_core="$CROSS_COMPILE"            \
  CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
  CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
  CFG_ARM64_core=y || exit 1
