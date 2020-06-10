# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../threadcxx.edl)

add_custom_command(
  OUTPUT threadcxx_t.h threadcxx_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  threadcxx_enc
  UUID
  209fac8d-dea1-4ed6-8160-5d6f3fdac61d
  CXX
  SOURCES
  enc.cpp
  cond_tests.cpp
  threadcxx_t.c)

enclave_include_directories(threadcxx_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
