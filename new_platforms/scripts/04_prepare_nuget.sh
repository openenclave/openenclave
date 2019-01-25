#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

mkdir -p nuget/native/gcc6/optee/v3.0.0

cp -R build/vexpress-qemu_virt/out/lib nuget/native/gcc6/optee/v3.0.0/vexpress-qemu_virt
cp -R build/vexpress-qemu_armv8a/out/lib nuget/native/gcc6/optee/v3.0.0/vexpress-qemu_armv8a
cp -R build/ls-ls1012grapeboard/out/lib nuget/native/gcc6/optee/v3.0.0/ls-ls1012grapeboard
