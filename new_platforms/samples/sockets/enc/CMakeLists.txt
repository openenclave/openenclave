# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_ex)

oeedl_file(${CMAKE_CURRENT_LIST_DIR}/../sockets.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

add_enclave_ex(
    TARGET sockets_enclave
    UUID aac3129e-c244-4e09-9e61-d4efcf31bca3
    SOURCES
        sockets.c
        ${GEN})
