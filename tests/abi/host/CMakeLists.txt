# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../abi.edl)

add_custom_command(
  OUTPUT abi_u.h abi_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND ABI_HOST_SRC abi_u.c)
if (WIN32)
  # Use clang to compile the inline assembly on Windows as well.
  add_custom_command(
    OUTPUT host.obj
    DEPENDS abi_u.h host.cpp
    COMMAND
      clang -c -O2 -m64 -I${PROJECT_SOURCE_DIR}/include
      -I${CMAKE_CURRENT_BINARY_DIR} -I${OE_INCDIR} -I${PROJECT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/host.cpp -o host.obj)
  list(APPEND ABI_HOST_SRC ${CMAKE_CURRENT_BINARY_DIR}/host.obj abi.asm)
else ()
  list(APPEND ABI_HOST_SRC host.cpp)
endif ()

add_executable(abi_host ${ABI_HOST_SRC})

string(TOUPPER "${CMAKE_BUILD_TYPE}" UPPERCASE_CMAKE_BUILD_TYPE)
if (NOT UPPERCASE_CMAKE_BUILD_TYPE STREQUAL "DEBUG" AND CMAKE_CXX_COMPILER_ID
                                                        MATCHES "GNU")
  target_compile_definitions(abi_host PRIVATE GCC_RELEASE)
endif ()

target_include_directories(abi_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                            ${PROJECT_SOURCE_DIR})

target_link_libraries(abi_host oehost)
