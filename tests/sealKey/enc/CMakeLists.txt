# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../sealKey.edl enclave gen)

add_enclave(TARGET sealKey_enc UUID ab200889-df37-440e-9c5c-e78a9ce6579e CXX SOURCES enc.cpp ${gen})

target_include_directories(sealKey_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(sealKey_enc PRIVATE cxx_generalized_initializers)
