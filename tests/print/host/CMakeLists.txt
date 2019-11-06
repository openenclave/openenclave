# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../print.edl host gen)

add_executable(print_host host.cpp ${gen})

target_include_directories(print_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(print_host oehostapp)
