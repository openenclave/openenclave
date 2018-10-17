# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
    # Produce single untrusted file
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/all_t.c

    # Run edger8r
    COMMAND 
        ${OE_BINDIR}/oeedger8r ${CMAKE_CURRENT_SOURCE_DIR}/../edl/all.edl 
            --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../edl
            --trusted

    # Regenerate if any edl file changes
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../edl/*.edl
)

# Copy generated c file to cpp file.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/all_t.cpp
    COMMAND 
        ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_BINARY_DIR}/all_t.c
                ${CMAKE_CURRENT_BINARY_DIR}/all_t.cpp
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/all_t.c
)

include(add_enclave_executable)

add_executable(edl_enc
    testarray.cpp
    testbasic.cpp 
    testenum.cpp 
    testforeign.cpp
    testmisc.cpp
    testpointer.cpp
    teststring.cpp
    teststruct.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/all_t.cpp
    )

target_include_directories(edl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_compile_options(edl_enc PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

target_link_libraries(edl_enc oelibcxx oeenclave)
