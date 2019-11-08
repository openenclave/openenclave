# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../test_datagram.edl host gen --edl-search-dir ../../../device/edl)

add_executable(datagram_host host.c ${gen})

target_include_directories(datagram_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(datagram_host oehostapp)
