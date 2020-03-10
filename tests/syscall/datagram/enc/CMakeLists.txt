# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../test_datagram.edl
    enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET datagram_enc SOURCES enc.c ${gen})

enclave_link_libraries(datagram_enc oelibc oehostsock oeenclave)
