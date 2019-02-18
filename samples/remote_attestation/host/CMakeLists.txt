# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../remoteattestation.edl host gen)

add_executable(remote_attestation_host host.cpp ${gen})

target_include_directories(remote_attestation_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(remote_attestation_host oehostapp)

