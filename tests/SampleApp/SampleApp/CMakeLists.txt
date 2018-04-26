# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(SampleApp sign.conf private.pem
    CallWrappers.cpp
    SampleApp.cpp
    )
target_link_libraries(SampleApp oecore)
