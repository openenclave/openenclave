# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

check_submodule_not_empty(SymCrypt-OpenSSL)

set(OPENSSL_3_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl_3)
set(SYMCRYPT_COMMON_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/SymCrypt-OpenSSL/ScosslCommon)
set(SYMCRYPT_PROVIDER_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/SymCrypt-OpenSSL/SymCryptProvider)

configure_file(${SYMCRYPT_PROVIDER_DIR}/inc/p_scossl_base.h.in
               ${SYMCRYPT_PROVIDER_DIR}/inc/p_scossl_base.h)

# Use CACHE so that the variables can be globally accessible
set(SYMCRYPT_VERSION_MAJOR
    "103"
    CACHE INTERNAL "")
set(SYMCRYPT_VERSION_MINOR
    "8"
    CACHE INTERNAL "")
set(SYMCRYPT_VERSION_PATCH
    "0"
    CACHE INTERNAL "")
set(SYMCRYPT_VERSION
    "${SYMCRYPT_VERSION_MAJOR}.${SYMCRYPT_VERSION_MINOR}.${SYMCRYPT_VERSION_PATCH}"
    CACHE INTERNAL "")
set(SYMCRYPT_NAME
    "libsymcrypt.so.${SYMCRYPT_VERSION}"
    CACHE INTERNAL "")
# The linker only takes one number after ".so"
set(SYMCRYPT_LINK_NAME
    "libsymcrypt.so.${SYMCRYPT_VERSION_MAJOR}"
    CACHE INTERNAL "")

# Download the SymCrypt release package at config-time
# The SymCrypt OpenSSL provider build requires the SymCrypt header
include(FetchContent)
FetchContent_Declare(
  symcrypt_package_prov
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/SymCrypt
  URL https://github.com/microsoft/SymCrypt/releases/download/v103.8.0/symcrypt-linux-oe_full-amd64-release-103.8.0-53be637.tar.gz
  URL_HASH
    SHA256=0D5F279A00A15953A9D6DB8B78BBD07AAD169EA93BBEA729ECDA134889943A03)

# Make the downloaded package globally available
FetchContent_GetProperties(symcrypt_package_prov)
if (NOT symcrypt_package_prov_POPULATED)
  FetchContent_Populate(symcrypt_package_prov)
endif ()

add_enclave_library(
  oesymcryptprovider
  STATIC
  ${SYMCRYPT_PROVIDER_DIR}/src/asymcipher/p_scossl_rsa_cipher.c
  ${SYMCRYPT_PROVIDER_DIR}/src/ciphers/p_scossl_aes.c
  ${SYMCRYPT_PROVIDER_DIR}/src/ciphers/p_scossl_aes_aead.c
  ${SYMCRYPT_PROVIDER_DIR}/src/ciphers/p_scossl_aes_xts.c
  ${SYMCRYPT_PROVIDER_DIR}/src/kdf/p_scossl_hkdf.c
  ${SYMCRYPT_PROVIDER_DIR}/src/kdf/p_scossl_kbkdf.c
  ${SYMCRYPT_PROVIDER_DIR}/src/kdf/p_scossl_sshkdf.c
  ${SYMCRYPT_PROVIDER_DIR}/src/kdf/p_scossl_tls1prf.c
  ${SYMCRYPT_PROVIDER_DIR}/src/keyexch/p_scossl_dh.c
  ${SYMCRYPT_PROVIDER_DIR}/src/keyexch/p_scossl_ecdh.c
  ${SYMCRYPT_PROVIDER_DIR}/src/keymgmt/p_scossl_dh_keymgmt.c
  ${SYMCRYPT_PROVIDER_DIR}/src/keymgmt/p_scossl_ecc_keymgmt.c
  ${SYMCRYPT_PROVIDER_DIR}/src/keymgmt/p_scossl_rsa_keymgmt.c
  ${SYMCRYPT_PROVIDER_DIR}/src/mac/p_scossl_cmac.c
  ${SYMCRYPT_PROVIDER_DIR}/src/mac/p_scossl_hmac.c
  ${SYMCRYPT_PROVIDER_DIR}/src/mac/p_scossl_kmac.c
  ${SYMCRYPT_PROVIDER_DIR}/src/signature/p_scossl_ecdsa_signature.c
  ${SYMCRYPT_PROVIDER_DIR}/src/signature/p_scossl_rsa_signature.c
  ${SYMCRYPT_PROVIDER_DIR}/src/p_scossl_digests.c
  ${SYMCRYPT_PROVIDER_DIR}/src/p_scossl_rand.c
  ${SYMCRYPT_PROVIDER_DIR}/src/p_scossl_rsa.c
  ${SYMCRYPT_PROVIDER_DIR}/src/p_scossl_ecc.c
  ${SYMCRYPT_PROVIDER_DIR}/src/p_scossl_base.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_helpers.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_aes_aead.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_dh.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_ecc.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_hkdf.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_mac.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_rsa.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_sshkdf.c
  ${SYMCRYPT_COMMON_DIR}/src/scossl_tls1prf.c)

enclave_compile_definitions(oesymcryptprovider PRIVATE -D_AMD64_)

if (uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  enclave_compile_definitions(oesymcryptprovider PRIVATE -DDBG=1)
endif ()

enclave_include_directories(
  oesymcryptprovider
  PRIVATE
  ${SYMCRYPT_PROVIDER_DIR}/inc
  ${SYMCRYPT_PROVIDER_DIR}/src
  ${SYMCRYPT_COMMON_DIR}/inc
  ${SYMCRYPT_COMMON_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/SymCrypt/inc
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include_3 # for configuration.h
  ${OPENSSL_3_DIR}/include)

maybe_build_using_clangw(oesymcryptprovider)

if (UNIX)
  string(REPLACE "." ";" CLANG_VERSION_LIST ${CMAKE_C_COMPILER_VERSION})
  list(GET CLANG_VERSION_LIST 0 CLANG_MAJOR_VERSION)

  set(CLANG_INTRINSIC_HEADERS_SEARCH_PATH
      "/usr/lib/llvm-${CLANG_MAJOR_VERSION}/lib/clang/${CMAKE_C_COMPILER_VERSION}/include"
  )
elseif (WIN32)
  find_program(
    CLANG_COMPILER clang
    PATHS "C:/Program Files/LLVM/bin"
    NO_DEFAULT_PATH REQUIRED)
  get_filename_component(CLANG_COMPILER_ROOT_DIR ${CLANG_COMPILER} DIRECTORY)
  file(GLOB CLANG_INTRINSIC_HEADERS_SEARCH_PATH
       "${CLANG_COMPILER_ROOT_DIR}/../lib/clang/*/include")
endif ()

# Clang major version should match LLVM version
find_path(
  CLANG_INTRINSIC_HEADERS_DIR
  NAMES "emmintrin.h"
  PATHS ${CLANG_INTRINSIC_HEADERS_SEARCH_PATH}
  NO_DEFAULT_PATH)

if (CLANG_INTRINSIC_HEADERS_DIR)
  if (WIN32)
    # On Windows, the path includes spaces that the current clangw script cannot handle. As a workaround,
    # we copy the directory to the CMAKE_CURRENT_BINARY_DIR/include
    add_custom_target(
      clang_intrinsic_headers_copy_provider
      COMMAND ${CMAKE_COMMAND} -E copy_directory ${CLANG_INTRINSIC_HEADERS_DIR}
              ${CMAKE_CURRENT_BINARY_DIR}/include)

    add_enclave_dependencies(oesymcryptprovider
                             clang_intrinsic_headers_copy_provider)

    set(CLANG_INTRINSIC_HEADERS_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
  endif ()

  enclave_compile_options(oesymcryptprovider PRIVATE
                          -I${CLANG_INTRINSIC_HEADERS_DIR})
else ()
  message(
    FATAL_ERROR
      "Cannot find clang intrinstics header (required by SymCrypt OpenSSL provider) in ${CLANG_INTRINSIC_HEADERS_SEARCH_PATH}"
  )
endif ()

enclave_compile_options(
  oesymcryptprovider
  PRIVATE
  # Supress warnings from SymCrypt OpenSSL provider
  -Wno-shorten-64-to-32
  -Wno-sign-conversion
  -Wno-implicit-int-conversion
  -Wno-unknown-pragmas
  -Wno-unused-parameter
  # Supress warnings from clang intrinsitcs
  -Wno-bitwise-op-parentheses
  -Wno-implicit-int-float-conversion
  -Wno-shift-op-parentheses)

add_enclave_dependencies(oesymcryptprovider openssl_3_generated)

enclave_link_libraries(oesymcryptprovider PUBLIC oelibc oe_includes)

install_enclaves(
  TARGETS
  oesymcryptprovider
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
