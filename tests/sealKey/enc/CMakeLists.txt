# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../sealKey.edl enclave gen)

add_executable(sealKey_enc enc.cpp ${gen})

target_include_directories(sealKey_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(sealKey_enc PRIVATE cxx_generalized_initializers)
target_link_libraries(sealKey_enc oelibcxx oeenclave)
target_compile_options(sealKey_enc PRIVATE -Wconversion -Wpointer-arith)

