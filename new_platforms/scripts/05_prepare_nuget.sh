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

mkdir $TARGET || exit 1
mkdir -p nuget/tools || exit 1

# Copy the TA Dev Kits used to build the SDK into the NuGet package.
PLATFORM=vexpress-qemu_virt
mkdir $TARGET/$PLATFORM || exit 1
cp -R optee/$PLATFORM/export-ta_arm32 $TARGET/$PLATFORM/devkit || exit 1

PLATFORM=vexpress-qemu_armv8a
mkdir $TARGET/$PLATFORM || exit 1
cp -R optee/$PLATFORM/export-ta_arm64 $TARGET/$PLATFORM/devkit || exit 1

PLATFORM=ls-ls1012grapeboard
mkdir $TARGET/$PLATFORM || exit 1
cp -R optee/$PLATFORM/export-ta_arm64 $TARGET/$PLATFORM/devkit || exit 1

# Copy the SDK binaries into the NuGet package.
for LIBRARY in "${LIBRARIES[@]}"
do
    for PLATFORM in "${PLATFORMS[@]}"
    do
        cp -R build/$PLATFORM/out/lib/$LIBRARY.a $TARGET/$PLATFORM || exit 1
    done
done

# Copy the oeedger8r tool into the NuGet package, too.
cp build/oeedger8r nuget/tools || exit 1
