# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../print.edl host gen)

add_executable(print_host host.cpp ${gen})

target_include_directories(print_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(print_host oehostapp)
target_compile_options(print_host PRIVATE -Wconversion -Wpointer-arith)
