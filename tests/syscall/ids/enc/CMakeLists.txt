# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../test_ids.edl enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET ids_enc SOURCES enc.c main.c ${gen})

target_link_libraries(ids_enc oelibc oeenclave)
