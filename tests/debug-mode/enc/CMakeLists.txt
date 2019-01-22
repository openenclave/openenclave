# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../debug_mode.edl enclave gen)

add_enclave(TARGET no_debug_enc_unsigned SOURCES enc.c props.c ${gen})

add_enclave(TARGET no_debug_enc CONFIG sign.conf SOURCES enc.c props.c ${gen})

add_enclave(TARGET debug_enc CONFIG sign-debug.conf SOURCES enc.c props-debug.c ${gen})

add_enclave(TARGET debug_enc_unsigned SOURCES enc.c props-debug.c ${gen})


target_include_directories(no_debug_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(no_debug_enc oelibc)

target_include_directories(debug_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(debug_enc oelibc)

target_include_directories(no_debug_enc_unsigned PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(no_debug_enc_unsigned oelibc)

target_include_directories(debug_enc_unsigned PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(debug_enc_unsigned oelibc)
