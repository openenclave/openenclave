# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../thread.edl host gen)

add_executable(thread_host host.cpp rwlocks_test_host.cpp ${gen})

target_include_directories(thread_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(thread_host oehostapp)
