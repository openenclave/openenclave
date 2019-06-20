# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("Sample: TLS connection between a non_enclave client and an enclave" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)

add_custom_target(tls_between_non_enc_client_enclave
                  DEPENDS tls_server tls_non_enc_client)
