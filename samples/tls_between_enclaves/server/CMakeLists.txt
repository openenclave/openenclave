# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

#find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enc)
add_subdirectory(host)

add_custom_target(tls_server DEPENDS tls_server_host tls_server_enc tls_server_sign_enc)

#if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
#  add_custom_target(run
#    DEPENDS tls_server_host sign
#    #   COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
#    COMMAND ${CMAKE_BINARY_DIR}/host/tls_server_host ${CMAKE_BINARY_DIR}/enc/tls_server_enc.signed -port:12341)
#endif ()
