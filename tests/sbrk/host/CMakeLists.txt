# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../sbrk.edl host gen)

add_executable(sbrk_host host.c ${gen})

target_include_directories(sbrk_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sbrk_host oehostapp)
