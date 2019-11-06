# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../create_rapid.edl host gen)

add_executable(create_rapid_host host.cpp ${gen})

target_include_directories(create_rapid_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_rapid_host oehostapp)
