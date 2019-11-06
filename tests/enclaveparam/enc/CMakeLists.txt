# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../enclaveparam.edl enclave gen)

add_enclave(TARGET enclaveparam_enc UUID c0c6e0fe-7c40-485a-beaf-4145293cd69a SOURCES enc.c ${gen})

target_include_directories(enclaveparam_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(enclaveparam_enc oelibc)
