# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
cmake_minimum_required(VERSION 3.13)
project("Check Quote Provider")

find_library(SGX_DCAP_QL NAMES sgx_dcap_ql REQUIRED)

# Raise fatal error if sgx_dcap_ql library is not found.
if (NOT SGX_DCAP_QL)
  message(FATAL_ERROR "sgx_dcap_ql not found")
endif ()
