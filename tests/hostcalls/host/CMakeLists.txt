# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../hostcalls.edl host gen)

add_executable(hostcalls_host host.cpp ${gen})

target_include_directories(hostcalls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hostcalls_host oehostapp)
