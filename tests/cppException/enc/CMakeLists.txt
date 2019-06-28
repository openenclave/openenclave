# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../cppException.edl enclave gen)

add_enclave(TARGET cppException_enc UUID fdabde1a-a03a-4850-a07d-633eea54af92 CXX SOURCES enc.cpp cppException.cpp ${gen})

target_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)

target_include_directories(cppException_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
