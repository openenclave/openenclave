# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../abi.edl)

add_custom_command(
  OUTPUT abi_u.h abi_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND ABI_HOST_SRC host.cpp abi_u.c)
if (WIN32)
  list(APPEND ABI_HOST_SRC abi.asm)
endif ()

add_executable(abi_host ${ABI_HOST_SRC})

target_include_directories(abi_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(abi_host oehost)
