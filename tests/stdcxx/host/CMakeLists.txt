# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../stdcxx.edl host gen)

add_executable(stdcxx_host host.cpp ${gen})

target_include_directories(stdcxx_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(stdcxx_host oehostapp)
