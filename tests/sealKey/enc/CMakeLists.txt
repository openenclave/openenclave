# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(sealKey_enc sign.conf private.pem
    enc.cpp
    )

target_compile_features(sealKey_enc PRIVATE cxx_generalized_initializers)
target_link_libraries(sealKey_enc oeenclave oelibcxx oeenclave)
