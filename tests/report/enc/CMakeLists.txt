# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../tests.edl)

add_custom_command(
    OUTPUT tests_t.h tests_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET report_enc UUID 20b1a091-50da-4e57-b58c-0a8489cb64a6
  SOURCES enc.cpp datetime.cpp ../common/tests.cpp tests_t.c)

enclave_include_directories(report_enc PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../common)

enclave_link_libraries(report_enc oelibc)
