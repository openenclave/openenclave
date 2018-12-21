# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../abortStatus.edl enclave gen)

add_enclave(TARGET abortStatus_enc CXX SOURCES enc.cpp ${gen})

target_compile_features(abortStatus_enc PRIVATE cxx_generalized_initializers)

target_include_directories(abortStatus_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
