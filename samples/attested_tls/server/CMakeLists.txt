# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

#find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enc)
add_subdirectory(host)

add_custom_target(tls_server DEPENDS tls_server_host tls_server_enc tls_server_sign_enc)
