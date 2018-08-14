# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Custom command to copy edl files to binary enc folder
# and run oeedger8r on the edl files.
# Dependency is specified on the edl files in the source tree.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/*.edl
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/*_t.c
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/*_t.h    
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../*.edl ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${OE_BINDIR}/oeedger8r --untrusted basic.edl string.edl
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../*.edl
    DEPENDS oeedger8r
)
 
# Custom noop target that depends on edl files (and hence the
# oeedger8r outputs) produced by above custom command.
add_custom_target(
    run_oeedger8r_host
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/*.edl
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/*_t.c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/*_t.h
    DEPENDS oeedger8r
)

add_executable(edl_host 
    main.cpp
    testbasic.cpp
    teststring.cpp
)

# Make edl_enc depend on edl files and outputs using 
# the custom target.
add_dependencies(edl_host run_oeedger8r_host) 

target_include_directories(edl_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(edl_host PRIVATE -std=c++11)

target_link_libraries(edl_host oehostapp)
