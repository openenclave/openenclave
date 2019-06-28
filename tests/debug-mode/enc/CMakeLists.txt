# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../debug_mode.edl enclave gen)

add_enclave(TARGET no_debug_enc_unsigned UUID f10dc769-9849-4141-9dd5-12b7f78a56fd SOURCES enc.c props.c ${gen})

add_enclave(TARGET no_debug_enc UUID e90548a8-3146-4d09-86e3-ea2bc56b6543 CONFIG sign.conf SOURCES enc.c props.c ${gen})

add_enclave(TARGET debug_enc UUID 9c99c483-93de-41ef-9d8b-abb290a00f41 CONFIG sign-debug.conf SOURCES enc.c props-debug.c ${gen})

add_enclave(TARGET debug_enc_unsigned UUID 6e214c32-51ff-4bf4-ab81-e164bc67c154 SOURCES enc.c props-debug.c ${gen})


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
