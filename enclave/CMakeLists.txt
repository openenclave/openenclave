# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(core)
add_subdirectory(crypto)

if (OE_SGX)
  set(PLATFORM_SRC
      ../common/sgx/endorsements.c
      ../common/sgx/qeidentity.c
      ../common/sgx/quote.c
      ../common/sgx/report.c
      ../common/sgx/report_helper.c
      ../common/sgx/collateral.c
      ../common/sgx/sgxcertextensions.c
      ../common/sgx/sgxmeasure.c
      ../common/sgx/tcbinfo.c
      ../common/sgx/tlsverifier.c
      ../common/sgx/verifier.c
      sgx/attester.c
      sgx/report.c
      sgx/collateralinfo.c
      sgx/start.S)
  if (WITH_EEID)
    list(APPEND PLATFORM_SRC ../common/sgx/eeid_verifier.c ../common/sgx/eeid.c
         sgx/eeid_attester.c)
  endif ()
elseif (OE_TRUSTZONE)
  set(PLATFORM_SRC optee/report.c optee/start.S)
  message("TODO: ADD ARM files.")
endif ()

add_enclave_library(
  oeenclave
  STATIC
  attest_plugin.c
  ../common/attest_plugin.c
  ../common/custom_claims.c
  ../common/datetime.c
  ../common/sha.c
  asym_keys.c
  link.c
  tls_cert.c
  ${PLATFORM_SRC})

maybe_build_using_clangw(oeenclave)

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  enclave_compile_options(oeenclave PRIVATE -Wjump-misses-init)

  if (OE_TRUSTZONE)
    target_compile_options(oeenclave PUBLIC ${OE_TZ_TA_C_FLAGS})
  endif ()
endif ()

enclave_enable_code_coverage(oeenclave)

# Add location of the oeedger8r-generated trusted headers for internal
# functions implemented via EDL files.
enclave_include_directories(oeenclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/core)

enclave_link_libraries(oeenclave PUBLIC oecryptombed)
if (OE_TRUSTZONE)
  enclave_link_libraries(oeenclave PUBLIC oelibutee)
endif ()

set_enclave_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
install_enclaves(
  TARGETS
  oeenclave
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

if (WITH_EEID)
  enclave_compile_definitions(oeenclave PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()
