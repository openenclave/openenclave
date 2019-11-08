# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../file.edl host gen)

add_executable(file_host host.cpp ${gen})

target_include_directories(file_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(file_host oehostapp)
