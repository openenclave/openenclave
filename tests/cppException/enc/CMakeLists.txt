# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../cppException.edl enclave gen)

add_enclave(TARGET cppException_enc CXX SOURCES enc.cpp cppException.cpp ${gen})

target_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)

target_include_directories(cppException_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
