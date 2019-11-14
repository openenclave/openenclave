# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ssp.edl host gen)

add_executable(ssp_host host.cpp ${gen})

target_include_directories(ssp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ssp_host oehostapp)
