# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../libcsock.edl host gen)

add_executable(libcsock_host host.c ../client.c ../server.c ${gen})

target_include_directories(libcsock_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(libcsock_host oehostapp)
