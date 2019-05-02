# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../libcsock.edl enclave gen)

add_executable(libcsock_enc2 enc.c ../client.c ../server.c ${gen})

target_include_directories(libcsock_enc2 PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

add_definitions(-DOE_NEED_STDC_NAMES)

target_link_libraries(libcsock_enc2 oeposix oeenclave oehostsock)
