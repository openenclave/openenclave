# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/all.edl 
    host
    all_u
    --edl-search-dir ../moreedl
)

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl/bar.edl 
    host-headers
    bar_u
)


add_executable(edl_host 
    main.cpp
    bar.cpp
    foo.cpp
    testarray.cpp
    testbasic.cpp
    testenum.cpp
    testforeign.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${all_u}
    ${bar_u}
)

target_include_directories(edl_host PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)

set_property(
    TARGET edl_host
    PROPERTY CXX_STANDARD 11
)
target_link_libraries(edl_host oehostapp)
