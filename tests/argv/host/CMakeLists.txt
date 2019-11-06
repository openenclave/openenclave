# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../argv.edl host gen)

add_executable(argv_host host.c ${gen})

target_include_directories(argv_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(argv_host oehostapp)
