# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Adapted from https://crascit.com/2016/04/09/using-ccache-with-cmake/
cmake_minimum_required(VERSION 3.4)

find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
  # Set CCACHE_CPP2 to true to decrease compile times when using ccache in
  # combination with clang
  # Support Unix Makefiles and Ninja
  set(CMAKE_C_COMPILER_LAUNCHER export CCACHE_CPP2=true && "${CCACHE_PROGRAM}")
  set(CMAKE_CXX_COMPILER_LAUNCHER export CCACHE_CPP2=true &&
                                  "${CCACHE_PROGRAM}")
  message(STATUS "Using CCache")
else ()
  message(STATUS "Not using CCache")
endif ()
