# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/all.edl 
    enclave
    all_t
    --edl-search-dir ../moreedl
)

# Dummy target used for generating from EDL on demand.
add_custom_target(edl_gen DEPENDS ${all_t})

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl/bar.edl 
    enclave-headers
    bar_t
)

add_enclave(TARGET edl_enc CXX
    SOURCES
    bar.cpp
    config.cpp
    foo.cpp
    testaliasing.cpp
    testarray.cpp
    testbasic.cpp
    testenum.cpp
    testerrno.cpp
    testforeign.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${all_t}
    ${bar_t}
    )

# The tests intentionally use floats etc in size context.
# Disable warnings.
if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang OR USE_CLANGW)
    set_source_files_properties(
        ${all_t}
        PROPERTIES COMPILE_FLAGS "-Wno-conversion"
    )
    set_source_files_properties(
        testpointer.cpp
        teststring.cpp
        PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter"
    )      
endif()

target_include_directories(edl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
if (NOT WIN32)
  # Re-enable strict aliasing. TODO: Remove this when #1717 is resolved.
  target_compile_options(edl_enc PUBLIC -fstrict-aliasing -Werror=strict-aliasing)
endif ()

# This is a separate enclave specifically shared with the same host.
oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/other.edl
    enclave
    other_t
)

add_enclave(TARGET edl_other_enc CXX SOURCES testother.cpp ${other_t})
target_include_directories(edl_other_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
