#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

TARGET=nuget/lib/native/gcc6/optee/v3.3.0

declare -a LIBRARIES=(
    "liboeenclave"
    "liboehost"

    "liboestdio_enc"
    "liboestdio_host"

    "liboesocket_enc"
    "liboesocket_host"

    "libmbedcrypto"
    "libmbedx509"
)

declare -a PLATFORMS=(
    "vexpress-qemu_virt"
    "vexpress-qemu_armv8a"
    "ls-ls1012grapeboard"
)

mkdir -p $TARGET || exit 1
mkdir -p nuget/tools || exit 1

for PLATFORM in "${PLATFORMS[@]}"
do
    mkdir -p $TARGET/$PLATFORM || exit 1
done

for LIBRARY in "${LIBRARIES[@]}"
do
    for PLATFORM in "${PLATFORMS[@]}"
    do
        cp -R build/$PLATFORM/out/lib/$LIBRARY.a $TARGET/$PLATFORM || exit 1
    done
done

cp build/oeedger8r nuget/tools || exit 1
