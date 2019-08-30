# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_dcap_client_target)
include(oeedl_file)

oeedl_file(../tls.edl host gen)

add_executable(tls_host host.cpp ${gen})

target_include_directories(tls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tls_host oehostapp)

# On Windows, explicitly add the nuget dependencies for the DCAP client to the target executable
if (WIN32)
    add_dcap_client_target(tls_host_dcap_client)
    add_dependencies(tls_host tls_host_dcap_client)
endif ()
