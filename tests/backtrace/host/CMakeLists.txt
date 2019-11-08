# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../backtrace.edl host gen)

add_executable(backtrace_host host.cpp ${gen})

target_include_directories(backtrace_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(backtrace_host oehostapp)
