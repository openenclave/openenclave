# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(OE_TOOLCHAINS ${CMAKE_BINARY_DIR}/toolchains)

set(CMAKE_C_COMPILER ${OE_TOOLCHAINS}/aarch32/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER ${OE_TOOLCHAINS}/aarch32/bin/arm-linux-gnueabihf-g++)

set(OE_TA_TOOLCHAIN_PREFIX /usr/bin/arm-linux-gnueabi-)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
