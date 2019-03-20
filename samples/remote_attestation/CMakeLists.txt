# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10)

project("Remote Attestation Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(common)
add_subdirectory(enc1)
add_subdirectory(enc2)
add_subdirectory(host)

add_custom_target(run
  DEPENDS remote_attestation_host enclave_a_signed enclave_b_signed
  COMMAND remote_attestation_host ${CMAKE_BINARY_DIR}/enc1/enclave_a.signed ${CMAKE_BINARY_DIR}/enc2/enclave_b.signed)
