# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Toolchain file used for cross-compiling using clang.
SET(CMAKE_SYSTEM_NAME Linux)

include(CMakeForceCompiler)

CMAKE_FORCE_C_COMPILER(clang Clang)
CMAKE_FORCE_CXX_COMPILER(clang Clang)
