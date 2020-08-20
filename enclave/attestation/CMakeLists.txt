# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
  set(PLATFORM_SRC
      ${PROJECT_SOURCE_DIR}/common/sgx/endorsements.c
      ${PROJECT_SOURCE_DIR}/common/sgx/qeidentity.c
      ${PROJECT_SOURCE_DIR}/common/sgx/quote.c
      ${PROJECT_SOURCE_DIR}/common/sgx/report.c
      ${PROJECT_SOURCE_DIR}/common/sgx/report_helper.c
      ${PROJECT_SOURCE_DIR}/common/sgx/collateral.c
      ${PROJECT_SOURCE_DIR}/common/sgx/sgxcertextensions.c
      ${PROJECT_SOURCE_DIR}/common/sgx/sgxmeasure.c
      ${PROJECT_SOURCE_DIR}/common/sgx/tcbinfo.c
      ${PROJECT_SOURCE_DIR}/common/sgx/tlsverifier.c
      ${PROJECT_SOURCE_DIR}/common/sgx/verifier.c
      sgx/attester.c
      sgx/report.c
      sgx/collateralinfo.c)
  if (WITH_EEID)
    list(APPEND PLATFORM_SRC ${PROJECT_SOURCE_DIR}/common/sgx/eeid_verifier.c
         ${PROJECT_SOURCE_DIR}/common/sgx/eeid.c sgx/eeid_attester.c)
  endif ()
elseif (OE_TRUSTZONE)
  set(PLATFORM_SRC optee/report.c)
endif ()

add_enclave_library(
  oeattestation
  STATIC
  attest_plugin.c
  ${PROJECT_SOURCE_DIR}/common/attest_plugin.c
  ${PROJECT_SOURCE_DIR}/common/custom_claims.c
  ${PROJECT_SOURCE_DIR}/common/datetime.c
  ${PROJECT_SOURCE_DIR}/common/sha.c
  asym_keys.c
  tls_cert.c
  ${PLATFORM_SRC})

maybe_build_using_clangw(oeattestation)

enclave_enable_code_coverage(oeattestation)

add_enclave_dependencies(oeattestation platform_trusted_edl)

# Add location of the oeedger8r-generated trusted headers for internal
# functions implemented via EDL files.
enclave_include_directories(oeattestation PRIVATE
                            ${CMAKE_BINARY_DIR}/enclave/core)

enclave_link_libraries(oeattestation PUBLIC oecryptombed)
if (OE_TRUSTZONE)
  enclave_link_libraries(oeattestation PUBLIC oelibutee)
endif ()

set_enclave_property(TARGET oeattestation PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
install_enclaves(
  TARGETS
  oeattestation
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

if (WITH_EEID)
  enclave_compile_definitions(oeattestation PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()
