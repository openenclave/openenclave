# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../test_datagram.edl
    enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET datagram_enc SOURCES enc.c ${gen})

target_link_libraries(datagram_enc oelibc oehostsock oeenclave)
