#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# -------------------------------------
# Package Prerequisites
# -------------------------------------

echo Installing Prerequisites

sudo apt-get update
sudo apt-get -y install android-tools-adb android-tools-fastboot autoconf     \
    automake bc bison build-essential cscope curl device-tree-compiler        \
    doxygen flex ftp-upload gdisk iasl libattr1-dev libcap-dev libfdt-dev     \
    libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev  \
    libssl-dev libtool make mtools netcat python-crypto python-serial         \
    python-wand unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev            \
    gcc-arm-linux-gnueabi graphviz gcc-aarch64-linux-gnu                      \
    g++-aarch64-linux-gnu sshpass cmake
