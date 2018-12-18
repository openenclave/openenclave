# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../edl/all.edl 
    enclave
    all_t
    --edl-search-dir ../moreedl
)

oeedl_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../moreedl/bar.edl 
    enclave-headers
    bar_t
)

add_executable(edl_enc
    bar.cpp
    config.cpp
    foo.cpp
    testarray.cpp
    testbasic.cpp 
    testenum.cpp 
    testforeign.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${all_t}
    ${bar_t}
    )


# The tests intentionally use floats etc in size context.
# Disable warnings.
if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
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
target_link_libraries(edl_enc oelibcxx oeenclave)
