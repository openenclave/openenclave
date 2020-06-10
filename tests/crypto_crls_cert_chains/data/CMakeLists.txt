# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# OS-specific configuration
if (UNIX)
  set(BUILD_OPT --bash)
elseif (WIN32)
  set(BUILD_OPT --gitbash)
else ()
  message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif ()

# These are specifically the byproducts that will be directly consumed by crypto_crls_cert_chains tests
set(CRYPTO_CRLS_DATA
    root.cert.pem
    intermediate.cert.pem
    leaf1.cert.pem
    leaf2.cert.pem
    root_crl1.der
    root_crl2.der
    intermediate_crl1.der
    intermediate_crl2.der)

add_custom_command(
  COMMAND
    ${OE_BASH} -c
    "${CMAKE_CURRENT_SOURCE_DIR}/make-test-certs ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${BUILD_OPT}"
  OUTPUT ${CRYPTO_CRLS_DATA})

add_custom_target(crypto_crls_cert_chains_test_data DEPENDS ${CRYPTO_CRLS_DATA})
