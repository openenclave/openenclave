# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Top-level CMake file for OpenEnclave samples.
#
cmake_minimum_required(VERSION 3.5.1)

# define project, take version from "VERSION" file
project("openenclave-samples" LANGUAGES C CXX)

# allow simpler include() of our scripts
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(compilersettings)

# yes, we want tests
enable_testing()
# enable valgrind via "ctest -D ExperimentalMemCheck"
include(CTest)

# set default paths
include(GNUInstallDirs)

# This is the interestin bit: import openenclave targets
include(${OE_PREFIX}/share/openenclave/openenclave.cmake)

# the OE host side needs threads
# TODO: Find a way to pass this on through the exported targets
find_package(Threads REQUIRED)

# finally, add all sample dirs
add_subdirectory(echo)
add_subdirectory(hello)
add_subdirectory(idl-file)
add_subdirectory(sort)
