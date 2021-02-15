# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
cmake_minimum_required(VERSION 3.13)
project("Check Quote Provider")

if (WIN32)
  # cmake documentation says that CMAKE_FIND_LIBRARY_SUFFIXES is typically .lib
  # and .dll.
  # https://cmake.org/cmake/help/v3.12/variable/CMAKE_FIND_LIBRARY_SUFFIXES.html
  # However, it is initialized to only .lib on Windows. Therefore, we explicitly
  # set the suffix to .dll.
  # See also: http://cmake.3232098.n2.nabble.com/find-library-doesn-t-find-dll-on-windows-td7597643.html
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
endif ()

find_library(SGX_DCAP_QL NAMES sgx_dcap_ql REQUIRED)

# Raise fatal error if sgx_dcap_ql library is not found.
if (NOT SGX_DCAP_QL)
  message(FATAL_ERROR "sgx_dcap_ql not found")
endif ()
