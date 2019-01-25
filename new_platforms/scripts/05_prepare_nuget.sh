#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

mkdir -p nuget/lib/native/gcc6/optee/v3.3.0
mkdir -p nuget/tools

cp -R build/vexpress-qemu_virt/out/lib nuget/lib/native/gcc6/optee/v3.0.0/vexpress-qemu_virt
cp -R build/vexpress-qemu_armv8a/out/lib nuget/lib/native/gcc6/optee/v3.0.0/vexpress-qemu_armv8a
cp -R build/ls-ls1012grapeboard/out/lib nuget/lib/native/gcc6/optee/v3.0.0/ls-ls1012grapeboard

cp build/oeedger8r nuget/tools
