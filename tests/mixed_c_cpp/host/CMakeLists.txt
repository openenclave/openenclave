# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
oeedl_file(../mixed.edl host gen)

add_executable(mixed_c_cpp_host host.cpp ${gen})

target_include_directories(mixed_c_cpp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(mixed_c_cpp_host oehostapp)
target_compile_options(mixed_c_cpp_host PRIVATE -Wconversion -Wpointer-arith)
