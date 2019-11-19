# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../zigzag.edl host gen)

add_executable(zigzag_host host.c ${gen})

target_include_directories(zigzag_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(zigzag_host oehostapp)
