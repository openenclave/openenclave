# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(
  oecryptombedtls
  STATIC
  ../../../common/asn1.c
  ../../../common/cert.c
  ../../../common/kdf.c
  asn1.c
  cert.c
  crl.c
  ctr_drbg.c
  ec.c
  cmac.c
  hmac.c
  key.c
  rsa.c
  sha.c)

maybe_build_using_clangw(oecryptombedtls)

enclave_enable_code_coverage(oecryptombedtls)

enclave_link_libraries(oecryptombedtls PUBLIC mbedcrypto)

set_enclave_property(TARGET oecryptombedtls PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
install_enclaves(
  TARGETS
  oecryptombedtls
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

if (WITH_EEID)
  enclave_compile_definitions(oecryptombedtls PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()
