# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(cppException_enc sign.conf private.pem
    enc.cpp
    cppException.cpp
    )

target_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)
target_compile_options(cppException_enc PRIVATE -Wno-terminate)
target_link_libraries(cppException_enc oelibcxx oeenclave)
