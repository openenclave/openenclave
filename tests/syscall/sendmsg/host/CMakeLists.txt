# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../sendmsg.edl host gen)

add_executable(sendmsg_host host.c ../client.c ../server.c ${gen})

target_include_directories(sendmsg_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sendmsg_host oehostapp)
