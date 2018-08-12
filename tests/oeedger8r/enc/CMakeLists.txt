# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


# Custom command to copy edl files to binary enc folder
# and run oeedger8r on the edl files.
# Dependency is specified on the edl files in the source tree.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/*.edl
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../*.edl ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${OE_BINDIR}/oeedger8r basic.edl
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../*.edl
)
 
# Custom noop target that depends on edl files (and hence the
# oeedger8r outputs) produced by above custom command.
add_custom_target(
    run_oeedger8r
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/*.edl
)

include(add_enclave_executable)

add_enclave_executable(edl_enc sign.conf private.pem
    testbasic.cpp        
    )

# Make edl_enc depend on edl files and outputs using 
# the custom target.
add_dependencies(edl_enc run_oeedger8r) 

target_include_directories(edl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(edl_enc PRIVATE -std=c++11)

target_link_libraries(edl_enc oeenclave)
