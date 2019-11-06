# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../switchless.edl host gen)

add_executable(switchless_host host.c ${gen})

target_include_directories(switchless_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_host oehostapp)
