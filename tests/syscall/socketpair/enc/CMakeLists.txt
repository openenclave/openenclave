# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../socketpair_test.edl)

add_custom_command(
  OUTPUT socketpair_test_t.h socketpair_test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

add_enclave(TARGET socketpair_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/socketpair_test_t.c)

enclave_include_directories(socketpair_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(socketpair_enc oelibc oehostsock)
