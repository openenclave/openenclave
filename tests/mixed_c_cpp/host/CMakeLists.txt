# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../mixed.edl host gen)

add_executable(mixed_c_cpp_host host.cpp ${gen})

target_include_directories(mixed_c_cpp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(mixed_c_cpp_host oehostapp)
