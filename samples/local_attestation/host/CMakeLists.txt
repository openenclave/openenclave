# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT localattestation_u.h localattestation_u.c localattestation_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/localattestation.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/localattestation.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(local_attestation_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/localattestation_u.c)

if (WIN32)
  copy_oedebugrt_target(local_attestation_host_oedebugrt)
  add_dependencies(local_attestation_host local_attestation_host_oedebugrt)
endif ()

target_include_directories(
  local_attestation_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(local_attestation_host openenclave::oehost)
