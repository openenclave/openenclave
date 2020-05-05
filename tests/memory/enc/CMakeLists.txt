# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../memory.edl)

add_custom_command(
  OUTPUT memory_t.h memory_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  memory_enc
  UUID
  719ff522-610b-43bd-9991-c4d52a91a7e1
  SOURCES
  basic.c
  boundaries.c
  enc.c
  stress.c
  fragment.c
  memory_t.c)

if (WIN32)
  enclave_compile_definitions(memory_enc PRIVATE NO_PAGING_SUPPORT)
endif ()

enclave_include_directories(memory_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(memory_enc oelibc oecore)
