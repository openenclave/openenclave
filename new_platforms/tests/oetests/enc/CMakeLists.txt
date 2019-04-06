# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_ex)

oeedl_file(${CMAKE_CURRENT_LIST_DIR}/../oetests.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

add_enclave_ex(
    TARGET oetests_enclave
    UUID 3156152a-19d1-423c-96ea-5adf5675798f
    SOURCES
        oetests_enclave.c
        OETestTA.c
        ${GEN})
