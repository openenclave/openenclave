# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave)

oeedl_file(../[[project-name]].edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

add_enclave(
    TARGET [[project-name]]_enclave
    UUID [[generated-uuid]]
    SOURCES
        enc.c
        ${GEN}
    C_GEN ${C_GEN})
