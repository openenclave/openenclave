# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../threadcxx.edl host gen)

add_executable(threadcxx_host host.cpp ${gen})

target_include_directories(threadcxx_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(threadcxx_host oehostapp)
