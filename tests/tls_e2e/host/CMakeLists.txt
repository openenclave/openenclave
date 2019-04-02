# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#include(oeedl_file)

oeedl_file(../tls_e2e.edl host gen)

add_executable(tls_e2e_host host.cpp tls_e2e_u.c ${gen})

target_include_directories(tls_e2e_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

#target_link_libraries(tls_e2e_host oehostresolver_host)
target_link_libraries(tls_e2e_host oehostapp)
