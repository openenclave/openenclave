# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sgx_zerobase.edl)

add_custom_command(
  OUTPUT sgx_zerobase_u.h sgx_zerobase_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sgx_zerobase_host host.cpp sgx_zerobase_u.c)

target_include_directories(
  sgx_zerobase_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

# TODO issue #4130: Need to find a way around hard-coding host application base address
# on the application CMakeList.txt.
target_link_libraries(sgx_zerobase_host oehost -Wl,-Ttext-segment,0x10000000)

target_link_libraries(sgx_zerobase_host oehost)
