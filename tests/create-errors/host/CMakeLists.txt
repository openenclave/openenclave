# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../create_errors.edl host gen)

add_executable(create_errors_host host.c ${gen})

target_include_directories(create_errors_host PRIVATE
                           ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(create_errors_host oehostapp)
