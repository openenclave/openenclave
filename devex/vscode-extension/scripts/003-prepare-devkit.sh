#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# NOTE: The final result of this script will be devdata.tar.gz.

EMU_PATH=emu

# Clone the SDK
if [ ! -d sdk ]; then
    git clone --recursive --depth=1 https://github.com/openenclave/openenclave sdk
fi

# Delete all previous output
if [ -d build ]; then
    rm -rf build
fi

if [ -d payload ]; then
    rm -rf payload
fi

# OP-TEE Build Output Folders
mkdir -p build/optee/vexpress-qemu_armv8a
mkdir -p build/optee/ls-ls1012grapeboard

# SDK Build Output
mkdir -p build/sdk/sgx
mkdir -p build/sdk/optee/vexpress-qemu_armv8a
mkdir -p build/sdk/optee/ls-ls1012grapeboard

# Extension Payload
mkdir -p payload/sdk/optee
mkdir -p payload/sdk/optee/vexpress-qemu_armv8a
mkdir -p payload/sdk/optee/ls-ls1012grapeboard

# Source Paths
OE_SDK_PATH=$PWD/sdk
OPTEE_PATH=$OE_SDK_PATH/3rdparty/optee/optee_os

# Output Paths
OPTEE_QEMU_ARMV8_OUT_PATH=$PWD/build/optee/vexpress-qemu_armv8a
OPTEE_GRAPEBOARD_OUT_PATH=$PWD/build/optee/ls-ls1012grapeboard

OE_SDK_SGX_OUT_PATH=$PWD/build/sdk/sgx
OE_SDK_QEMU_ARMV8_OUT_PATH=$PWD/build/sdk/optee/vexpress-qemu_armv8a
OE_SDK_GRAPEBOARD_OUT_PATH=$PWD/build/sdk/optee/ls-ls1012grapeboard

PAYLOAD_QEMU_ARMV8_PATH=$PWD/payload/sdk/optee/vexpress-qemu_armv8a
PAYLOAD_GRAPEBOARD_PATH=$PWD/payload/sdk/optee/ls-ls1012grapeboard

# OP-TEE Build Flags
OPTEE_FLAGS=$(cat << EOF
platform-cflags-optimization=-Os 
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

# Cross-compiler Prefixes
CROSS_COMPILE=aarch64-linux-gnu-
TA_CROSS_COMPILE=aarch64-linux-gnu-
TA_CROSS_COMPILE_32=arm-linux-gnueabi-

if hash ccache 2>/dev/null; then
    CROSS_COMPILE="ccache $CROSS_COMPILE"
    TA_CROSS_COMPILE="ccache $TA_CROSS_COMPILE"
    TA_CROSS_COMPILE_32="ccache $TA_CROSS_COMPILE_32"
fi

# Build OP-TEE for QEMU ARMv8
pushd "$OPTEE_QEMU_ARMV8_OUT_PATH" || exit
# shellcheck disable=SC2086
ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"        \
    PLATFORM=vexpress-qemu_armv8a                  \
    O="$PWD"                                       \
    $OPTEE_FLAGS                                   \
    CROSS_COMPILE="$CROSS_COMPILE"                 \
    CROSS_COMPILE_core="$CROSS_COMPILE"            \
    CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
    CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
    CFG_ARM64_core=y || exit
popd || exit

# Build OP-TEE for the Scalys Grapeboard
pushd "$OPTEE_GRAPEBOARD_OUT_PATH" || exit
# shellcheck disable=SC2086
ARCH=arm make -j"$(nproc)" -C "$OPTEE_PATH"        \
    PLATFORM=ls-ls1012grapeboard                   \
    O="$PWD"                                       \
    $OPTEE_FLAGS                                   \
    CROSS_COMPILE="$CROSS_COMPILE"                 \
    CROSS_COMPILE_core="$CROSS_COMPILE"            \
    CROSS_COMPILE_ta_arm64="$TA_CROSS_COMPILE"     \
    CROSS_COMPILE_ta_arm32="$TA_CROSS_COMPILE_32"  \
    CFG_ARM64_core=y || exit
popd || exit

# Clear OP-TEE build variables
unset CROSS_COMPILE
unset TA_CROSS_COMPILE
unset TA_CROSS_COMPILE_32

# Build the SDK for Intel SGX
pushd "$OE_SDK_SGX_OUT_PATH" || exit
cmake -G Ninja "$OE_SDK_PATH"                       \
    -DCMAKE_BUILD_TYPE=Debug                        \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'  \
    -DCPACK_GENERATOR=DEB || exit
ninja package || exit

mkdir expand
pushd expand || exit
7z x ../*.deb || exit
tar xf data.tar || exit
popd || exit

popd || exit  # SDK Build Done

# Build the SDK for OP-TEE on QEMU ARMv8
pushd "$OE_SDK_QEMU_ARMV8_OUT_PATH" || exit
DEV_KIT=$OPTEE_QEMU_ARMV8_OUT_PATH
cmake -G Ninja "$OE_SDK_PATH"                                    \
    -DCMAKE_BUILD_TYPE=Debug                                     \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'               \
    -DCPACK_GENERATOR=DEB                                        \
    -DHAS_QUOTE_PROVIDER=OFF                                     \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake  \
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit
ninja package || exit

mkdir expand
pushd expand || exit
7z x ../*.deb || exit
tar xf data.tar || exit
popd || exit

popd || exit # SDK Build Done

# Build the SDK for OP-TEE on the Scalys Grapeboard
pushd "$OE_SDK_GRAPEBOARD_OUT_PATH" || exit
DEV_KIT=$OPTEE_GRAPEBOARD_OUT_PATH
cmake -G Ninja "$OE_SDK_PATH"                                    \
    -DCMAKE_BUILD_TYPE=Debug                                     \
    -DCMAKE_INSTALL_PREFIX:PATH='/opt/openenclave'               \
    -DCPACK_GENERATOR=DEB                                        \
    -DHAS_QUOTE_PROVIDER=OFF                                     \
    -DCMAKE_TOOLCHAIN_FILE="$OE_SDK_PATH"/cmake/arm-cross.cmake  \
    -DOE_TA_DEV_KIT_DIR="$DEV_KIT"/export-ta_arm64 || exit 1
ninja package || exit

mkdir expand
pushd expand || exit
7z x ../*.deb || exit
tar xf data.tar || exit
popd || exit

popd || exit # SDK Build Done

unset DEV_KIT

# Collect output into the extension's payload
cp "$OPTEE_QEMU_ARMV8_OUT_PATH"/export-ta_arm64/keys/default_ta.pem payload/sdk/optee/
cp "$OPTEE_QEMU_ARMV8_OUT_PATH"/export-ta_arm64/src/ta.ld.S         payload/sdk/optee/
cp "$OPTEE_QEMU_ARMV8_OUT_PATH"/export-ta_arm64/scripts/sign.py     payload/sdk/optee/

cp -r "$OE_SDK_QEMU_ARMV8_OUT_PATH"/expand/opt/openenclave/* "$PAYLOAD_QEMU_ARMV8_PATH"/
cp -r "$OE_SDK_GRAPEBOARD_OUT_PATH"/expand/opt/openenclave/* "$PAYLOAD_GRAPEBOARD_PATH"/

# Replace the ARMv8 version of oeedger8r with the x64 one for cross-compilation
mv "$PAYLOAD_QEMU_ARMV8_PATH"/bin/oeedger8r "$PAYLOAD_QEMU_ARMV8_PATH"/bin/oeedger8r.aarch64
mv "$PAYLOAD_GRAPEBOARD_PATH"/bin/oeedger8r "$PAYLOAD_GRAPEBOARD_PATH"/bin/oeedger8r.aarch64

cp "$OE_SDK_SGX_OUT_PATH"/expand/opt/openenclave/bin/oeedger8r "$PAYLOAD_QEMU_ARMV8_PATH"/bin/oeedger8r
cp "$OE_SDK_SGX_OUT_PATH"/expand/opt/openenclave/bin/oeedger8r "$PAYLOAD_GRAPEBOARD_PATH"/bin/oeedger8r

# Copy the emulator
cp -r "$EMU_PATH" payload/emu

# Zip everything up
pushd payload || exit
tar cvzf ../devdata.tar.gz emu/ sdk/
popd || exit
