#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$SOURCES_PATH=$1
$BUILD_TYPE=$2

# -------------------------------------
# Build Open Enclave SDK
# -------------------------------------

echo Building Open Enclave SDK

TA_DEV_KIT_BASE_PATH=$PWD/optee

# Create directory structure for build output.
if [ ! -d build ]; then
    mkdir build
fi
pushd build

if [ ! -d vexpress-qemu_armv8a ]; then
    mkdir vexpress-qemu_armv8a
fi

# Build for QEMU AARCH64.
pushd vexpress-qemu_armv8a

cmake $SOURCES_PATH                                                                   \
      -G Ninja                                                                        \
      -DCMAKE_BUILD_TYPE=$BUILD_TYPE                                                  \
      -DCMAKE_TOOLCHAIN_FILE=$SOURCES_PATH/cmake/arm-cross.cmake                      \
      -DOE_TA_DEV_KIT_DIR=$TA_DEV_KIT_BASE_PATH/vexpress-qemu_armv8a/export-ta_arm64  \
      -DUSE_LIBSGX=OFF                                                                \
      -Wdev || exit 1

ninja -v || exit 1

popd  # vexpress-qemu_armv8a

popd  # build
