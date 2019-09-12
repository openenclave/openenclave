# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(OUTPUT matrix_t.h matrix_t.c matrix_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/matrix.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/matrix.edl)

add_executable(enclave
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/matrix_t.c
    ${CMAKE_SOURCE_DIR}/common/multiply.c
    ${CMAKE_SOURCE_DIR}/common/multiply.h)

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

target_include_directories(enclave PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclave openenclave::oeenclave openenclave::oelibc)
