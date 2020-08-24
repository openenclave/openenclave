# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

check_submodule_not_empty(mbedtls)

# Load the compiler info if we're cross compiling on Windows.
if (USE_CLANGW)
  include(toolchain-clangw.cmake)
endif ()

# We use configure_file since the config.h file has #cmakedefines in it, so
# the C header changes if we're running in debug mode or not. This will copy
# the config file to the build directory.
string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)
if ("${CMAKE_BUILD_TYPE}" STREQUAL "DEBUG")
  set(MBEDTLS_CERTS_C TRUE)
  set(MBEDTLS_DEBUG_C TRUE)
endif ()
configure_file(config.h config.h)

# Compiler flags is copied from the mbedtls CMakeLists.txt and
# mbedtls/library/CMakeLists.txt files, so that we can compile with the same warnings.
string(REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_C_COMPILER_ID}")
string(REGEX MATCH "GNU" CMAKE_COMPILER_IS_GNU "${CMAKE_C_COMPILER_ID}")

set(MBEDTLS_COMPILE_OPTS
    -W -Wdeclaration-after-statement -Wwrite-strings -Wshadow
    # Disable conversion warnings inherited from OE.
    -Wno-sign-conversion -Wno-conversion)

if (CMAKE_COMPILER_IS_GNU)
  list(APPEND MBEDTLS_COMPILE_OPTS -Wlogical-op -Wmissing-declarations
       -Wmissing-prototypes)
endif ()

if (CMAKE_COMPILER_IS_CLANG)
  list(
    APPEND
    MBEDTLS_COMPILE_OPTS
    -Wpointer-arith
    -Wimplicit-fallthrough
    -Wmissing-declarations
    -Wmissing-prototypes
    -Wdocumentation
    -Wno-documentation-deprecated-sync
    -Wunreachable-code)
endif ()

if (USE_CLANGW)
  list(APPEND MBEDTLS_COMPILE_OPTS "-target x86_64-pc-linux")

  # Set up the linker.
  find_program(LLVM_AR "llvm-ar.exe")
  set(CMAKE_AR ${LLVM_AR})
endif ()

# Sources for the three mbedtls libraries. We name the mbedcrypto library
# as "mbedcrypto_static" because the exported target for all 3 mbedtls
# libraries in OE is called "mbedcrypto."
add_enclave_library(
  mbedcrypto_static
  STATIC
  mbedtls/library/aes.c
  mbedtls/library/aesni.c
  mbedtls/library/arc4.c
  mbedtls/library/aria.c
  mbedtls/library/asn1parse.c
  mbedtls/library/asn1write.c
  mbedtls/library/base64.c
  mbedtls/library/bignum.c
  mbedtls/library/blowfish.c
  mbedtls/library/camellia.c
  mbedtls/library/ccm.c
  mbedtls/library/chacha20.c
  mbedtls/library/chachapoly.c
  mbedtls/library/cipher.c
  mbedtls/library/cipher_wrap.c
  mbedtls/library/cmac.c
  mbedtls/library/ctr_drbg.c
  mbedtls/library/des.c
  mbedtls/library/dhm.c
  mbedtls/library/ecdh.c
  mbedtls/library/ecdsa.c
  mbedtls/library/ecjpake.c
  mbedtls/library/ecp.c
  mbedtls/library/ecp_curves.c
  mbedtls/library/entropy.c
  mbedtls/library/entropy_poll.c
  mbedtls/library/error.c
  mbedtls/library/gcm.c
  mbedtls/library/havege.c
  mbedtls/library/hkdf.c
  mbedtls/library/hmac_drbg.c
  mbedtls/library/md.c
  mbedtls/library/md2.c
  mbedtls/library/md4.c
  mbedtls/library/md5.c
  mbedtls/library/md_wrap.c
  mbedtls/library/memory_buffer_alloc.c
  mbedtls/library/nist_kw.c
  mbedtls/library/oid.c
  mbedtls/library/padlock.c
  mbedtls/library/pem.c
  mbedtls/library/pk.c
  mbedtls/library/pk_wrap.c
  mbedtls/library/pkcs12.c
  mbedtls/library/pkcs5.c
  mbedtls/library/pkparse.c
  mbedtls/library/pkwrite.c
  mbedtls/library/platform.c
  mbedtls/library/platform_util.c
  mbedtls/library/poly1305.c
  mbedtls/library/ripemd160.c
  mbedtls/library/rsa.c
  mbedtls/library/rsa_internal.c
  mbedtls/library/sha1.c
  mbedtls/library/sha256.c
  mbedtls/library/sha512.c
  mbedtls/library/threading.c
  mbedtls/library/timing.c
  mbedtls/library/version.c
  mbedtls/library/version_features.c
  mbedtls/library/xtea.c
  # Since we define mbedtls to use an alternate entropy source, it uses an
  # undefined mebdtls_hardware_poll function. We define it to avoid
  # circular library dependecies.
  mbedtls_hardware_poll.c)

add_enclave_library(
  mbedx509
  STATIC
  mbedtls/library/certs.c
  mbedtls/library/pkcs11.c
  mbedtls/library/x509.c
  mbedtls/library/x509_create.c
  mbedtls/library/x509_crl.c
  mbedtls/library/x509_crt.c
  mbedtls/library/x509_csr.c
  mbedtls/library/x509write_crt.c
  mbedtls/library/x509write_csr.c)

add_enclave_library(
  mbedtls
  STATIC
  mbedtls/library/debug.c
  mbedtls/library/net_sockets.c
  mbedtls/library/ssl_cache.c
  mbedtls/library/ssl_ciphersuites.c
  mbedtls/library/ssl_cli.c
  mbedtls/library/ssl_cookie.c
  mbedtls/library/ssl_srv.c
  mbedtls/library/ssl_ticket.c
  mbedtls/library/ssl_tls.c)

# Make sure that we build with clang on Windows.
maybe_build_using_clangw(mbedcrypto_static)
maybe_build_using_clangw(mbedx509)
maybe_build_using_clangw(mbedtls)

# Change the mbedcrypto_static target to the real mbedcrypto library name.
set_target_properties(mbedcrypto_static PROPERTIES OUTPUT_NAME "mbedcrypto")
if (LVI_MITIGATION MATCHES ControlFlow)
  set_target_properties(mbedcrypto_static-lvi-cfg
                        PROPERTIES OUTPUT_NAME "mbedcrypto-lvi-cfg")
endif ()

# Add the custom config file in the build interface only.
# In the install interface, we will just replace the default
# config file.
enclave_compile_definitions(
  mbedcrypto_static PUBLIC
  $<BUILD_INTERFACE:MBEDTLS_CONFIG_FILE=<config.h$<ANGLE-R>>)

enclave_compile_options(mbedcrypto_static PRIVATE ${MBEDTLS_COMPILE_OPTS})
enclave_compile_options(mbedx509 PRIVATE ${MBEDTLS_COMPILE_OPTS})
enclave_compile_options(mbedtls PRIVATE ${MBEDTLS_COMPILE_OPTS})

# We include ${CMAKE_CURRENT_BINARY_DIR} because the generated config.h
# from the configure_file is located there.
enclave_include_directories(
  mbedcrypto_static
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty>)

# Link all the libraries.
enclave_link_libraries(mbedcrypto_static PUBLIC oelibc oe_includes)
enclave_link_libraries(mbedx509 PUBLIC mbedcrypto_static)
enclave_link_libraries(mbedtls PUBLIC mbedx509)

# Install the include files and the static libraries.
install_enclaves(
  TARGETS
  mbedcrypto_static
  mbedx509
  mbedtls
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include/mbedtls
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/config.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/mbedtls/)

# Create mbedcrypto export target.
add_enclave_library(mbedcrypto INTERFACE)
enclave_link_libraries(mbedcrypto INTERFACE mbedtls)
install_enclaves(TARGETS mbedcrypto EXPORT openenclave-targets)
