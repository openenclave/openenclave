# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test_dup.edl)

add_custom_command(
  OUTPUT test_dup_t.h test_dup_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../device/edl)

add_enclave(TARGET dup_enc SOURCES enc.c main.c
            ${CMAKE_CURRENT_BINARY_DIR}/test_dup_t.c)

enclave_link_libraries(dup_enc oelibc oehostfs oeenclave)
