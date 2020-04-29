#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# NOTE: This script should run on Ubuntu 18.04, preferably in a container to
#       avoid tainting the system with otherwise unnecessary packages. This
#       all works well with LXD.

# Install prerequisites
sudo apt update && sudo apt install -y android-tools-adb                       \
    android-tools-fastboot autoconf automake bc bison build-essential ccache   \
    cgdb cscope curl device-tree-compiler expect flex ftp-upload gdb-multiarch \
    gdisk iasl libattr1-dev libc6 libcap-dev libfdt-dev libftdi-dev            \
    libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev libssl-dev    \
    libstdc++6 libtool libz1 make mtools netcat python-crypto                  \
    python-pyelftools python-serial python-wand python3-pyelftools repo unzip  \
    uuid-dev xdg-utils xterm xz-utils zlib1g-dev coreutils

SCRIPT_PATH=$(dirname "$(realpath -s "${BASH_SOURCE[0]}")")

# Build folder
mkdir emulator
pushd emulator || exit

# Initialize the source repositories for the entire emulated system
repo init -u https://github.com/ms-iot/optee_manifest -m oe_qemu_v8.xml -b oe-3.6.0
# -> You may have to answer prompts.

# Fetch the sources
repo sync -j"$(nproc)"

# The build repository contains the Makefiles
cd build || exit

# Apply debug flags to OP-TEE and prevent spawning XTerms during the build
git apply "$SCRIPT_PATH"/patches/001-Build-OP-TEE-Debug-Flags-no-XTerm.patch

# Add init script to mount the host filesystem and copy TAs on boot
cp "$SCRIPT_PATH"/patches/S51copytas br-ext/board/qemu/overlay/etc/init.d/

# Download Linaro toolchains for ARM32/64
make toolchains -j2

# Build it all and start the emulator
make run -j"$(nproc)"

popd || exit

#
# Manual Steps:
#
# 1. Ensure that the emulator works:
#    a. Let it boot (QEMU command: continue);
#    b. Log in (username: root, no password)
#    c. Run xtest
# 2. Stop the emulator (Ctrl-C);
# 3. Run the packaging script.
#
