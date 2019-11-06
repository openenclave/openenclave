# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../libunwind.edl host gen)

add_executable(libunwind_host host.cpp ${gen})

target_include_directories(libunwind_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(libunwind_host oehostapp)
