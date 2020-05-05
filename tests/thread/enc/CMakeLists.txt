# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread.edl)

add_custom_command(
  OUTPUT thread_t.h thread_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  pthread_enc
  UUID
  abe989c7-b167-4cc8-9653-c18a0bdc66da
  CXX
  SOURCES
  enc.cpp
  cond_tests.cpp
  rwlock_tests.cpp
  errno_tests.cpp
  thread_t.c)

add_enclave(
  TARGET
  oethread_enc
  UUID
  35c689f8-f752-4896-9c83-ec16dc7bd10e
  CXX
  SOURCES
  enc.cpp
  cond_tests.cpp
  rwlock_tests.cpp
  errno_tests.cpp
  thread_t.c)

enclave_compile_definitions(pthread_enc PRIVATE -D_PTHREAD_ENC_)

enclave_include_directories(pthread_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

enclave_include_directories(oethread_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
