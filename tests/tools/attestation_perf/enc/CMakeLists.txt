# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT attestation_perf_t.h attestation_perf_t.c attestation_perf_args.h
  DEPENDS ../attestation_perf.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../attestation_perf.edl
          --search-path ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_enclave(
  TARGET
  attestation_perf_enc
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/attestation_perf_t.c
  CONFIG
  enc.conf)

# Need for the generated file attestation_perf_t.h
enclave_include_directories(attestation_perf_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(attestation_perf_enc oeenclave oelibc)

# Generate the enclave binary in the the same directory with the attestation_perf binary
set_enclave_properties(attestation_perf_enc PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                       "${CMAKE_CURRENT_BINARY_DIR}/..")
