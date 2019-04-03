# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave)

oeedl_file(${CMAKE_CURRENT_LIST_DIR}/../localattestation.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

add_enclave(
    TARGET localattestation_enclave
    UUID 97d140f4-5f59-4d1f-9735-cb21d49e7eb7
    SOURCES
        enc.c
        ${GEN}
    C_GEN ${C_GEN})
