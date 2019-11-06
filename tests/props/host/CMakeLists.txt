# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../props.edl host gen)

add_executable(props_host host.c ${gen})

target_include_directories(props_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(props_host oehostapp)
