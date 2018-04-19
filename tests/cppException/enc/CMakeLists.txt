# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(cppExceptionEnc sign.conf private.pem
    enc.cpp
    cppException.cpp
    )

target_compile_features(cppExceptionEnc PRIVATE cxx_generalized_initializers)
target_compile_options(cppExceptionEnc PRIVATE -Wno-terminate)
target_link_libraries(cppExceptionEnc oelibcxx oecore)
