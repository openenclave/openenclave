# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project("[[project-name]]" VERSION ${OE_VERSION} LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "[[sdk-folder]]/new_platforms/cmake")

add_subdirectory([[sdk-folder]]/new_platforms)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)

add_subdirectory(enc)
add_subdirectory(host)
