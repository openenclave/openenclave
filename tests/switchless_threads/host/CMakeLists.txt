# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../switchless_threads.edl host gen)

add_executable(switchless_threads_host host.c ${gen})

target_include_directories(switchless_threads_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_threads_host oehostapp)
