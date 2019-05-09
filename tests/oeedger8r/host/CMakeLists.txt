# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

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

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/other.edl
    host
    other_u
)

add_executable(edl_host 
    main.cpp
    bar.cpp
    foo.cpp
    testarray.cpp
    testbasic.cpp
    testenum.cpp
    testerrno.cpp
    testforeign.cpp
    testother.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${all_u}
    ${bar_u}
    ${other_u}
)

# The tests intentionally use floats etc in size context.
# Disable warnings.
if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
    set_source_files_properties(
        ${all_u}
        PROPERTIES COMPILE_FLAGS "-Wno-conversion"
    )
    set_source_files_properties(
        testpointer.cpp
        teststring.cpp
        PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter"
    )    
endif()

target_include_directories(edl_host PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
if (NOT WIN32)
  # Re-enable strict aliasing. TODO: Remove this when #1717 is resolved.
  target_compile_options(edl_host PUBLIC -fstrict-aliasing -Werror=strict-aliasing)
endif ()
target_link_libraries(edl_host oehostapp)
