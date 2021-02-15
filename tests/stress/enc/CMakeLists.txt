# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../stress.edl)

add_custom_command(
  OUTPUT stress_t.h stress_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET stress_enc SOURCES enc.cpp
            ${CMAKE_CURRENT_BINARY_DIR}/stress_t.c)

enclave_include_directories(stress_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(stress_enc oelibc)
