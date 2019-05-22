#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$SOURCES_PATH=$1

# -------------------------------------
# Build OP-TEE
# -------------------------------------

echo Building OP-TEE

# Create a directory structure for output.
if [ ! -d optee ]; then
    mkdir optee
fi

if [ ! -d optee/vexpress-qemu_armv8a ]; then
    mkdir optee/vexpress-qemu_armv8a
fi

# Path to OP-TEE within the Open Enclave SDK.
OPTEE_OS_PATH=$SOURCES_PATH/3rdparty/optee/optee_os

# Compilation flags shared across platforms.
OPTEE_FLAGS=platform-cflags-optimization=-Os  \
            CFG_CRYPTO_SIZE_OPTIMIZATION=y    \
            CFG_PAGED_USER_TA=n               \
            CFG_REE_FS=n                      \
            CFG_RPMB_FS=y                     \
            CFG_RPMB_TESTKEY=y                \
            CFG_RPMB_WRITE_KEY=n              \
            CFG_RPMB_RESET_FAT=n              \
            CFG_TEE_CORE_DEBUG=y              \
            CFG_TEE_CORE_LOG_LEVEL=2          \
            CFG_TEE_TA_LOG_LEVEL=4            \
            CFG_UNWIND=n                      \
            CFG_WITH_PAGER=n                  \
            CFG_WITH_USER_TA=y

# Build for QEMU AARCH64.
CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-
TA_CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-
TA_CROSS_COMPILE_32=/usr/bin/arm-linux-gnueabihf-

ARCH=arm make -j$(nproc) -C $OPTEE_OS_PATH               \
    PLATFORM=vexpress-qemu_armv8a                \
    O=$PWD/optee/vexpress-qemu_armv8a            \
    $OPTEE_FLAGS                                 \
    CROSS_COMPILE=$CROSS_COMPILE                 \
    CROSS_COMPILE_core=$CROSS_COMPILE            \
    CROSS_COMPILE_ta_arm64=$TA_CROSS_COMPILE     \
    CROSS_COMPILE_ta_arm32=$TA_CROSS_COMPILE_32  \
    CFG_ARM64_core=y                             \
    || exit 1
