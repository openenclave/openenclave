# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../resolver_test.edl
    host resolver_test_u
    --edl-search-dir ../../../include
)

add_executable(resolver_host
    host.c
    ${resolver_test_u}
)

target_link_libraries(resolver_host oehostresolver_host)
target_include_directories(resolver_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(resolver_host oehostapp)
