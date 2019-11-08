# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../libcxx.edl host gen)

add_executable(libcxx_host host.cpp ${gen})

target_link_libraries(libcxx_host oehostapp)

target_include_directories(libcxx_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
