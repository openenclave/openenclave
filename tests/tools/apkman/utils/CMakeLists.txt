# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE pthread.edl)

add_custom_command(
  OUTPUT pthread_t.h pthread_u.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
          ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

if (BUILD_ENCLAVES)
  add_enclave_library(oeencpthread STATIC pthread_enc.c pthread_t.h)

  enclave_link_libraries(oeencpthread PRIVATE oelibc)
  enclave_include_directories(oeencpthread PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
endif ()

add_library(oehostpthread STATIC pthread_host.c pthread_u.h)

target_link_libraries(oehostpthread oehost)
target_include_directories(oehostpthread PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
