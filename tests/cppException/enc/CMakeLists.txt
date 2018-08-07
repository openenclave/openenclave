# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_compile_flags_if_supported)

include(add_enclave_executable)
add_enclave_executable(cppException_enc sign.conf private.pem
    enc.cpp
    cppException.cpp
    )

target_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)
add_target_cxx_compile_flags_if_supported(cppException_enc
    -Wno-error=terminate
    -Wno-error=exceptions
    )
target_link_libraries(cppException_enc oelibcxx oeenclave)
