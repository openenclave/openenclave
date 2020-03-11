# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(OUTPUT oecert_t.h oecert_t.c oecert_args.h
  DEPENDS ../oecert.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecert.edl)

add_enclave(TARGET oecert_enc SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/oecert_t.c)

# Need for the generated file oecert_t.h
enclave_include_directories(oecert_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(oecert_enc oeenclave oelibc)
