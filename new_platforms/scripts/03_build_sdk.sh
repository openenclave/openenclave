#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# -------------------------------------
# Build Open Enclave SDK
# -------------------------------------

echo Building Open Enclave SDK

TOOLCHAINS_PATH=$PWD/toolchains
NP_PATH=$SOURCES_PATH/new_platforms
TA_DEV_KIT_BASE_PATH=$PWD/optee

# Create directory structure for build output.
if [ ! -d build ]; then
    mkdir build
fi
pushd build

if [ ! -d vexpress-qemu_virt ]; then
    mkdir vexpress-qemu_virt
fi
if [ ! -d vexpress-qemu_armv8a ]; then
    mkdir vexpress-qemu_armv8a
fi
if [ ! -d ls-ls1012grapeboard  ]; then
    mkdir ls-ls1012grapeboard
fi

# Download oeedger8r.
wget $OEEdger8rLinuxURI || exit 1
PATH=$PWD:$PATH

# Build for QEMU ARM.
pushd vexpress-qemu_virt

ln -s $TOOLCHAINS_PATH .

cmake -DOE_TEE=TZ                                                                \
      -DTA_DEV_KIT_DIR=$TA_DEV_KIT_BASE_PATH/vexpress-qemu_virt/export-ta_arm32  \
      -DCMAKE_TOOLCHAIN_FILE=$NP_PATH/cmake/linux-arm-v6.cmake                   \
      $NP_PATH || exit 1

cmake --build . -- -j

popd  # vexpress-qemu_virt

# Build for QEMU AARCH64.
pushd vexpress-qemu_armv8a

ln -s $TOOLCHAINS_PATH .

cmake -DOE_TEE=TZ                                                                  \
      -DTA_DEV_KIT_DIR=$TA_DEV_KIT_BASE_PATH/vexpress-qemu_armv8a/export-ta_arm64  \
      -DCMAKE_TOOLCHAIN_FILE=$NP_PATH/cmake/linux-aarch64-v6.cmake                 \
      $NP_PATH || exit 1

cmake --build . -- -j

popd  # vexpress-qemu_armv8a

# Build for the LS-1012.
pushd ls-ls1012grapeboard

ln -s $TOOLCHAINS_PATH .

cmake -DOE_TEE=TZ                                                                 \
      -DTA_DEV_KIT_DIR=$TA_DEV_KIT_BASE_PATH/ls-ls1012grapeboard/export-ta_arm64  \
      -DCMAKE_TOOLCHAIN_FILE=$NP_PATH/cmake/linux-aarch64-v6.cmake                \
      $NP_PATH || exit 1

cmake --build . -- -j

popd  # ls-ls1012grapeboard

popd  # build
