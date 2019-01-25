#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

TARGET=nuget/lib/native/gcc6/optee/v3.3.0

mkdir -p $TARGET || exit 1
mkdir -p nuget/tools || exit 1

cp -R build/vexpress-qemu_virt/out/lib $TARGET/vexpress-qemu_virt || exit 1
cp -R build/vexpress-qemu_armv8a/out/lib $TARGET/vexpress-qemu_armv8a || exit 1
cp -R build/ls-ls1012grapeboard/out/lib $TARGET/ls-ls1012grapeboard || exit 1

cp build/oeedger8r nuget/tools || exit 1
