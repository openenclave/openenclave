# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.



oeedl_file(../props.edl enclave gen)

add_enclave(TARGET props_enc UUID 3c1786e3-568f-4185-9ffa-1f198c98393e CONFIG sign.conf SOURCES enc.c props.c ${gen})
add_enclave(TARGET props_enc_unsigned UUID 14ade1b6-900b-4b5a-9b90-f115254e0293 SOURCES enc.c props.c ${gen})

target_include_directories(props_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(props_enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(props_enc oelibc)
target_link_libraries(props_enc_unsigned oelibc)
