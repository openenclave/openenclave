# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../socket_test.edl)

add_custom_command(
  OUTPUT socket_test_t.h socket_test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

add_enclave(TARGET socket_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/socket_test_t.c)

enclave_include_directories(socket_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(socket_enc oelibc oehostsock)
