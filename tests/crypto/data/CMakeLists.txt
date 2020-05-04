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

# These are specifically the byproducts that will be directly consumed by crypto tests
set(CRYPTO_TEST_DATA
    asn1.cert.pem
    coordinates.bin
    ec_cert_with_ext.pem
    ec_cert_crl_distribution.pem
    intermediate.crl.der
    intermediate.cert.pem
    intermediate.ec.cert.pem
    intermediate2.cert.pem
    leaf.key.pem
    leaf.cert.pem
    leaf.ec.cert.pem
    leaf.public.key.pem
    leaf_modulus.hex
    leaf2.cert.pem
    root.crl.der
    root.cert.pem
    root.ec.cert.pem
    root.ec.key.pem
    root.ec.public.key.pem
    root2.cert.pem
    self_signed.cert.der
    test_ec_signature
    test_rsa_signature
    time.txt)

add_custom_command(
  COMMAND
    ${OE_BASH} -c
    "${CMAKE_CURRENT_SOURCE_DIR}/make-test-certs ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${BUILD_OPT}"
  OUTPUT ${CRYPTO_TEST_DATA})

add_custom_target(crypto_test_data DEPENDS ${CRYPTO_TEST_DATA})
