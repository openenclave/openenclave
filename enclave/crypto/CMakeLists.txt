# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(
  oecryptombed
  STATIC
  ../../common/asn1.c
  ../../common/cert.c
  ../../common/kdf.c
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

maybe_build_using_clangw(oecryptombed)

enclave_link_libraries(oecryptombed PUBLIC mbedcrypto)

set_enclave_property(TARGET oecryptombed PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
install_enclaves(
  TARGETS
  oecryptombed
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
