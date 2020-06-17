# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT remoteattestation_u.h remoteattestation_u.c remoteattestation_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/remoteattestation.edl
  COMMAND
    openenclave::oeedger8r --untrusted
    ${CMAKE_SOURCE_DIR}/remoteattestation.edl --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(remote_attestation_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/remoteattestation_u.c)
target_include_directories(
  remote_attestation_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
          ${CMAKE_CURRENT_BINARY_DIR})

if (WIN32)
  add_dcap_client_target(remote_attestation_dcap_target)
  add_dependencies(remote_attestation_host remote_attestation_dcap_target)
  copy_oedebugrt_target(remote_attestation_oedebugrt_target)
  add_dependencies(remote_attestation_host remote_attestation_oedebugrt_target)
endif ()

target_link_libraries(remote_attestation_host openenclave::oehost)
