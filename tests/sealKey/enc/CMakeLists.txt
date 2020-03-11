# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../sealKey.edl)

add_custom_command(
    OUTPUT sealKey_t.h sealKey_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sealKey_enc UUID ab200889-df37-440e-9c5c-e78a9ce6579e CXX SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/sealKey_t.c)

enclave_include_directories(sealKey_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})

enclave_compile_features(sealKey_enc PRIVATE cxx_generalized_initializers)
