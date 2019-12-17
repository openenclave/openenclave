# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../sbrk.edl enclave gen)

add_enclave(TARGET sbrk_enc
    UUID 0b6b308f-71be-4adb-8793-baf63698e288 SOURCES enc.c ${gen})

target_include_directories(sbrk_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sbrk_enc oelibc)
