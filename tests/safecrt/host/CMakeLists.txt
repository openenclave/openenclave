# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../safecrt.edl host gen)

add_executable(safecrt_host
    ../common/test.cpp
    host.cpp
    ${gen}
)

target_include_directories(safecrt_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(safecrt_host oehostapp)
