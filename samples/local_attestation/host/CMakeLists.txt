# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../localattestation.edl host gen)

add_executable(local_attestation_host host.cpp ${gen})

target_include_directories(local_attestation_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(local_attestation_host oehostapp)

