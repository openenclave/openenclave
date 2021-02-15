# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.1)

# Set CMAKE_BUILD_TYPE if not specified
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif ()

if (NOT ";Debug;RelWithDebInfo;Release;" MATCHES ";${CMAKE_BUILD_TYPE};")
  message(
    FATAL_ERROR "CMAKE_BUILD_TYPE must be Debug, RelWithDebInfo or Release")
endif ()

project(sgxptrace)

find_library(DL_LIB NAMES dl)
add_library(dl SHARED IMPORTED)
set_target_properties(dl PROPERTIES IMPORTED_LOCATION ${DL_LIB})

find_package(Threads REQUIRED)

add_library(sgxptrace SHARED ptrace.c inferior_status.c enclave_context.c)

target_link_libraries(sgxptrace dl Threads::Threads)

target_compile_options(sgxptrace PRIVATE -Wall -Werror -Wno-attributes
                                         -Wmissing-prototypes -m64)

# RTLD_NEXT requires _GNU_SOURCE to be defined.
target_compile_definitions(sgxptrace PRIVATE -D_GNU_SOURCE)

set_property(TARGET sgxptrace PROPERTY TARGET_OUTPUT_DIRECTORY
                                       ${PROJECT_BINARY_DIR})
