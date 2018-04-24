# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(sealKeyEnc sign.conf private.pem
    enc.cpp
    )

target_compile_features(sealKeyEnc PRIVATE cxx_generalized_initializers)
target_link_libraries(sealKeyEnc oeenclave oelibcxx)
