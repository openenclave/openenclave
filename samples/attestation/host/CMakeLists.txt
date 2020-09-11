# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT attestation_u.h attestation_u.c attestation_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/attestation.edl
  COMMAND
    openenclave::oeedger8r --untrusted
    ${CMAKE_SOURCE_DIR}/attestation.edl --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(attestation_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/attestation_u.c)
target_include_directories(
  attestation_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
          ${CMAKE_CURRENT_BINARY_DIR})

if (WIN32)
  add_dcap_client_target(attestation_dcap_target)
  add_dependencies(attestation_host attestation_dcap_target)
  copy_oedebugrt_target(attestation_oedebugrt_target)
  add_dependencies(attestation_host attestation_oedebugrt_target)
endif ()

target_link_libraries(attestation_host openenclave::oehost)
