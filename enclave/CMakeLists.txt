# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(core)
add_subdirectory(crypto)
add_subdirectory(sealing)

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
      ${PROJECT_SOURCE_DIR}/common/tdx/quote.c
      ${PROJECT_SOURCE_DIR}/common/tdx/verifier.c
      sgx/attester.c
      sgx/report.c
      sgx/verifier.c
      sgx/tdx_verifier.c
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

# build oeenclave
# Usage:
# add_library_oeenclave_wrapper(<LIB_NAME name of lib> [SKIP_INSTALL])
macro (add_library_oeenclave_wrapper)
  set(options SKIP_INSTALL)
  set(oneValueArgs LIB_NAME)
  set(multiValueArgs)

  cmake_parse_arguments(PARA "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  add_enclave_library(
    ${PARA_LIB_NAME}
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

  maybe_build_using_clangw(${PARA_LIB_NAME})

  if (CMAKE_C_COMPILER_ID MATCHES GNU)
    enclave_compile_options(${PARA_LIB_NAME} PRIVATE -Wjump-misses-init)

    if (OE_TRUSTZONE)
      target_compile_options(${PARA_LIB_NAME} PUBLIC ${OE_TZ_TA_C_FLAGS})
    endif ()
  endif ()

  enclave_enable_code_coverage(${PARA_LIB_NAME})

  # Add location of the oeedger8r-generated trusted headers for internal
  # functions implemented via EDL files.
  enclave_include_directories(${PARA_LIB_NAME} PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR}/core)

  enclave_link_libraries(${PARA_LIB_NAME} PUBLIC oelibc)

  if (OE_TRUSTZONE)
    enclave_link_libraries(${PARA_LIB_NAME} PUBLIC oelibutee)
  endif ()

  if (NOT PARA_SKIP_INSTALL)
    set_enclave_property(
      TARGET ${PARA_LIB_NAME} PROPERTY ARCHIVE_OUTPUT_DIRECTORY
      ${OE_LIBDIR}/openenclave/enclave)
    install_enclaves(
      TARGETS
      ${PARA_LIB_NAME}
      EXPORT
      openenclave-targets
      ARCHIVE
      DESTINATION
      ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
  endif ()

  if (WITH_EEID)
    enclave_compile_definitions(${PARA_LIB_NAME} PRIVATE
                                OE_WITH_EXPERIMENTAL_EEID)
    # oeenclave currently does not link against the oecrypto* library by default.
    # Consequently, it does not inherit the include paths of the crypto (e.g., mbedtls)
    # headers, which are needed by eeid.c. Therefore, we add the paths here.
    enclave_include_directories(
      ${PARA_LIB_NAME} PRIVATE
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include>
      $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/3rdparty/mbedtls>)
  endif ()

  enclave_enable_fuzzing(${PARA_LIB_NAME})
endmacro ()

add_library_oeenclave_wrapper(LIB_NAME oeenclave)
# This lib should only be used to build oeutil
add_library_oeenclave_wrapper(LIB_NAME oeenclave_prerelease_test SKIP_INSTALL)
target_compile_definitions(
  oeenclave_prerelease_test PUBLIC OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
                                   OEUTIL_QUOTE_BYPASS_DATE_CHECK)
