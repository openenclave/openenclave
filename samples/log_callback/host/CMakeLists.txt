# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT log_callback_u.h log_callback_u.c log_callback_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/log_callback.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/log_callback.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(log_callback_host host.c
                                 ${CMAKE_CURRENT_BINARY_DIR}/log_callback_u.c)

if (WIN32)
  copy_oedebugrt_target(log_callback_host_oedebugrt)
  add_dependencies(log_callback_host log_callback_host_oedebugrt)
endif ()

target_include_directories(
  log_callback_host PRIVATE # Needed for the generated file log_callback_u.h
                            ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(log_callback_host openenclave::oehost)
