# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enc)
add_subdirectory(host)

add_custom_target(tls_client DEPENDS tls_client_host tls_client_enc tls_client_sign_enc)
