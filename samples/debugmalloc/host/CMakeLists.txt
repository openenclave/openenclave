# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT debugmalloc_u.h debugmalloc_u.c debugmalloc_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/debugmalloc.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/debugmalloc.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(debugmalloc_host host.c
                                ${CMAKE_CURRENT_BINARY_DIR}/debugmalloc_u.c)

if (WIN32)
  copy_oedebugrt_target(debugmalloc_host_oedebugrt)
  add_dependencies(debugmalloc_host debugmalloc_host_oedebugrt)
endif ()

target_include_directories(
  debugmalloc_host PRIVATE # Needed for the generated file debugmalloc_u.h
                           ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(debugmalloc_host openenclave::oehost)
