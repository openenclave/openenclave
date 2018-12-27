# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeenclave STATIC
    ../common/asn1.c
    ../common/cert.c
    ../common/datetime.c
    ../common/kdf.c
    ../common/qeidentity.c
    ../common/quote.c
    ../common/report.c
    ../common/revocation.c
    ../common/sgxcertextensions.c
    ../common/tcbinfo.c
    asn1.c
    asym_keys.c
    cert.c
    crl.c
    ec.c
    cmac.c
    hmac.c
    key.c
    link.c
    qeidinfo.c
    random.c
    report.c
    revocationinfo.c
    rsa.c
    sha.c
    start.S)

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oeenclave PRIVATE -Wjump-misses-init)
endif()

target_link_libraries(oeenclave PUBLIC
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

if (USE_CLANGW)
  # Mark assembler files for compilation using clang.
  set_source_files_properties(start.S  PROPERTIES LANGUAGE C)
  build_using_clangw(oeenclave)
endif()

