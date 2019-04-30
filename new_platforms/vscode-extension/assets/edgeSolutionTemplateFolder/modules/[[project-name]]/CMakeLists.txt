# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project("[[project-name]]" VERSION ${OE_VERSION} LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "/app/3rdparty/openenclave/new_platforms/cmake")

add_subdirectory(/app/3rdparty/openenclave/new_platforms EXCLUDE_FROM_ALL)

add_subdirectory(/app/enc)
add_subdirectory(/app/host)
