#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

OE_SDK_TAG=v0.11.0

# Clone the SDK
if [ ! -d sdk ]; then
    git clone --recursive --depth=1 https://github.com/openenclave/openenclave sdk -b $OE_SDK_TAG
fi

# Delete all previous output
if [ -d build ]; then
    rm -rf build
fi

if [ -f runner.bionic ]; then
    rm runner.bionic
fi

if [ -f runner.xenial ]; then
    rm runner.xenial
fi

# Build on Ubuntu 18.04 (Bionic) -- Builds OP-TEE, so must go first!
lxc exec oepkgbionic -- sudo --login --user ubuntu "$PWD/runner.sh" "$PWD" || exit 1

# Build on Ubuntu 16.04 (Xenial)
lxc exec oepkgxenial -- sudo --login --user ubuntu "$PWD/runner.sh" "$PWD" || exit 1
