# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)

add_custom_command(
  OUTPUT test_u.h test_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(wasm_host host.c test_u.c)

enclave_compile_options(wasm_host PRIVATE -Wno-visibility)

target_include_directories(wasm_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(wasm_host oehost)
