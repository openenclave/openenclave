#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if [ -d pack ]; then
    rm -rf pack
fi

function copy-includes {
    OS_CODENAME=$1
    PLATFORM=$2
    SUBPLATOFRM=$3
    BUILD_TYPE=$4
    PLATFORM_VERSION=$5

    SRC_BASE="$PWD/build/$OS_CODENAME/sdk/$PLATFORM/$PLATFORM_VERSION/$SUBPLATOFRM/$BUILD_TYPE/expand/opt/openenclave"
    DST_BASE="$PWD/pack/build/native/linux/$OS_CODENAME/$PLATFORM/$SUBPLATOFRM/$BUILD_TYPE"

    mkdir -p "$DST_BASE"
    cp -r "$SRC_BASE/include" "$DST_BASE"/
}

function copy-sgx-libs {
    OS_CODENAME=$1
    SGX_PLATFORM=$2
    BUILD_TYPE=$3
    CLANG_VERSION=$4

    SRC_BASE="$PWD/build/$OS_CODENAME/sdk/sgx/$SGX_PLATFORM/$BUILD_TYPE/expand/opt/openenclave"
    DST_BASE="$PWD/pack/lib/native/linux/$OS_CODENAME/sgx/$SGX_PLATFORM/$BUILD_TYPE"

    mkdir -p "$DST_BASE/cmake"
    mkdir -p "$DST_BASE/debugger"
    mkdir -p "$DST_BASE/enclave/clang-$CLANG_VERSION"
    mkdir -p "$DST_BASE/host/clang-$CLANG_VERSION"

    cp -r "$SRC_BASE"/lib/openenclave/cmake/* "$DST_BASE/cmake"
    cp -r "$SRC_BASE"/lib/openenclave/debugger/* "$DST_BASE/debugger"
    cp -r "$SRC_BASE"/lib/openenclave/enclave/* "$DST_BASE/enclave/clang-$CLANG_VERSION"
    cp -r "$SRC_BASE"/lib/openenclave/host/* "$DST_BASE/host/clang-$CLANG_VERSION"
}

function copy-optee-libs {
    OS_CODENAME=$1
    OPTEE_PLATFORM=$2
    BUILD_TYPE=$3
    GCC_VERSION=$4

    SRC_BASE="$PWD/build/$OS_CODENAME/sdk/optee/3.6.0/$OPTEE_PLATFORM/$BUILD_TYPE/expand/opt/openenclave"
    DST_BASE="$PWD/pack/lib/native/linux/$OS_CODENAME/optee/v3.6.0/$OPTEE_PLATFORM/$BUILD_TYPE"

    mkdir -p "$DST_BASE/cmake"
    mkdir -p "$DST_BASE/devkit"
    mkdir -p "$DST_BASE/enclave/gcc-$GCC_VERSION"
    mkdir -p "$DST_BASE/host/gcc-$GCC_VERSION"

    cp -r "$PWD"/build/optee/3.6.0/"$OPTEE_PLATFORM"/debug/export-ta_arm64/* "$DST_BASE"/devkit/

    cp -r "$SRC_BASE"/lib/openenclave/cmake/* "$DST_BASE/cmake/"
    cp -r "$SRC_BASE"/lib/openenclave/enclave/* "$DST_BASE/enclave/gcc-$GCC_VERSION/"
    cp -r "$SRC_BASE"/lib/openenclave/optee/libteec/* "$DST_BASE/enclave/gcc-$GCC_VERSION/"
    cp -r "$SRC_BASE"/lib/openenclave/host/* "$DST_BASE/host/gcc-$GCC_VERSION/"
}

function copy-sgx-tools {
    OS_CODENAME=$1
    SGX_PLATFORM=$2

    SRC_BASE="$PWD/build/$OS_CODENAME/sdk/sgx/$SGX_PLATFORM/release/expand/opt/openenclave"
    DST_BASE="$PWD/pack/tools/linux/$OS_CODENAME/sgx/$SGX_PLATFORM"

    mkdir -p "$DST_BASE"
    cp -r "$SRC_BASE"/bin/* "$DST_BASE"/
}

function copy-optee-tools {
    OS_CODENAME=$1

    SRC_ARM64_BASE="$PWD/build/$OS_CODENAME/sdk/optee/3.6.0/vexpress-qemu_armv8a/release/expand/opt/openenclave"
    SRC_X64_BASE="$PWD/build/$OS_CODENAME/sdk/sgx/default/release/expand/opt/openenclave"
    DST_BASE="$PWD/pack/tools/linux/$OS_CODENAME/optee"

    mkdir -p "$DST_BASE/arm64"
    mkdir -p "$DST_BASE/x64"

    cp -r "$SRC_ARM64_BASE/bin/oeedger8r" "$DST_BASE/arm64/"
    cp -r "$SRC_X64_BASE/bin/oeedger8r" "$DST_BASE/x64/"
}

# Copy libraries
copy-optee-libs xenial ls-ls1012grapeboard debug 5
copy-optee-libs xenial ls-ls1012grapeboard release 5
copy-optee-libs xenial vexpress-qemu_armv8a debug 5
copy-optee-libs xenial vexpress-qemu_armv8a release 5

copy-optee-libs bionic ls-ls1012grapeboard debug 5
copy-optee-libs bionic ls-ls1012grapeboard release 5
copy-optee-libs bionic vexpress-qemu_armv8a debug 5
copy-optee-libs bionic vexpress-qemu_armv8a release 5

copy-sgx-libs xenial default debug 7
copy-sgx-libs xenial default release 7

copy-sgx-libs bionic default debug 7
copy-sgx-libs bionic default release 7

# Copy tools
copy-sgx-tools xenial default
copy-sgx-tools bionic default

copy-optee-tools xenial
copy-optee-tools bionic

# Copy includes
copy-includes xenial sgx default debug
copy-includes xenial sgx default release

copy-includes xenial optee ls-ls1012grapeboard debug 3.6.0
copy-includes xenial optee ls-ls1012grapeboard release 3.6.0
copy-includes xenial optee vexpress-qemu_armv8a debug 3.6.0
copy-includes xenial optee vexpress-qemu_armv8a release 3.6.0

copy-includes bionic sgx default debug
copy-includes bionic sgx default release

copy-includes bionic optee ls-ls1012grapeboard debug 3.6.0
copy-includes bionic optee ls-ls1012grapeboard release 3.6.0
copy-includes bionic optee vexpress-qemu_armv8a debug 3.6.0
copy-includes bionic optee vexpress-qemu_armv8a release 3.6.0
