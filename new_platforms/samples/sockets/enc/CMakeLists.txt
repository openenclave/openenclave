# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave)

oeedl_file(../sockets.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

add_enclave(
    TARGET sockets_enclave
    UUID aac3129e-c244-4e09-9e61-d4efcf31bca3
    SOURCES
        sockets.c
        ${GEN}
    C_GEN ${C_GEN})
