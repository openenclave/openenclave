# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(SampleAppAttestationHost SampleAppAttestationHost.cpp)
target_link_libraries(SampleAppAttestationHost oehostapp)

target_compile_features(SampleAppAttestationHost PRIVATE cxx_generalized_initializers)
