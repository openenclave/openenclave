# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT switchless_sample_u.h switchless_sample_u.c switchless_sample_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/switchless_sample.edl
  COMMAND
    openenclave::oeedger8r --untrusted
    ${CMAKE_SOURCE_DIR}/switchless_sample.edl --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(switchless_host
               host.c ${CMAKE_CURRENT_BINARY_DIR}/switchless_sample_u.c)

if (WIN32)
  copy_oedebugrt_target(switchless_host_oedebugrt_target)
  add_dependencies(switchless_host switchless_host_oedebugrt_target)
endif ()

target_include_directories(
  switchless_host PRIVATE # Needed for the generated file switchless_sample_u.h
                          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(switchless_host openenclave::oehost)
