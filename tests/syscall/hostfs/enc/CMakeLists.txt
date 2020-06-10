# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test_hostfs.edl)

add_custom_command(
  OUTPUT test_hostfs_t.h test_hostfs_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../device/edl)

add_enclave(TARGET hostfs_enc SOURCES enc.c main.c
            ${CMAKE_CURRENT_BINARY_DIR}/test_hostfs_t.c)

enclave_link_libraries(hostfs_enc oelibc oehostfs oeenclave)
