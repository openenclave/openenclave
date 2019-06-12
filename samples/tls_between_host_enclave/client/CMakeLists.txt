# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_STANDARD 11)

add_executable(tls_client client.cpp identity_verifier.cpp verify_signer_openssl.cpp)

target_include_directories(tls_client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  -I/usr/include/openssl)

target_link_libraries(tls_client openenclave::oehostapp ssl)
