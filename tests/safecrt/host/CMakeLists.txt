# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../safecrt.edl host gen)

add_executable(safecrt_host
    ../common/test.cpp
    host.cpp
    ${gen}
)

target_include_directories(safecrt_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(safecrt_host oehostapp)
