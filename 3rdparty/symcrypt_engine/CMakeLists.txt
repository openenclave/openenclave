# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

check_submodule_not_empty(SymCrypt-OpenSSL)

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)
set(SYMCRYPT_ENGINE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/SymCrypt-OpenSSL/SymCryptEngine)

# Download the SymCrypt release package at config-time
# The SymCrypt OpenSSL engine build requires the SymCrypt header
include(FetchContent)
FetchContent_Declare(
  symcrypt_package
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/SymCrypt
  URL https://github.com/microsoft/SymCrypt/releases/download/SymCrypt_v100.20_master_2021-12-01T112555-0800_31fb2e9/symcrypt_AMD64_openenclave_100.20.0-31fb2e94-pre.tgz
  URL_HASH
    SHA256=8d08f459e57751cd94580395922be905f51c172dd06f3ea0db403febb7b53e3e)

# Make the downloaded package globally available
FetchContent_GetProperties(symcrypt_package)
if (NOT symcrypt_package_POPULATED)
  FetchContent_Populate(symcrypt_package)
endif ()

add_enclave_library(
  oesymcryptengine
  STATIC
  ${SYMCRYPT_ENGINE_DIR}/src/scossl.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_ciphers.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_dh.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_digests.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_dsa.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_ecc.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_helpers.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_hkdf.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_pkey_meths.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_rand.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_rsa.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_rsapss.c
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_tls1prf.c)

enclave_compile_definitions(oesymcryptengine PRIVATE -D_AMD64_)

if (uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  enclave_compile_definitions(oesymcryptengine PRIVATE -DDBG=1)
endif ()

enclave_include_directories(
  oesymcryptengine
  PRIVATE
  ${SYMCRYPT_ENGINE_DIR}/inc
  ${SYMCRYPT_ENGINE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/SymCrypt/inc
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include # for opensslconf.h
  ${OPENSSL_DIR}/include)

maybe_build_using_clangw(oesymcryptengine)

if (UNIX)
  string(REPLACE "." ";" CLANG_VERSION_LIST ${CMAKE_C_COMPILER_VERSION})
  list(GET CLANG_VERSION_LIST 0 CLANG_MAJOR_VERSION)

  set(CLANG_INTRINSIC_HEADERS_SEARCH_PATH
      "/usr/lib/llvm-${CLANG_MAJOR_VERSION}/lib/clang/${CMAKE_C_COMPILER_VERSION}/include"
  )
elseif (WIN32)
  # Update the string when the supported clang version is changed
  set(CLANG_VERSION "10.0.0")

  set(CLANG_INTRINSIC_HEADERS_SEARCH_PATH
      "C:/Program Files/LLVM/lib/clang/${CLANG_VERSION}/include")
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
      clang_intrinsic_headers_copy
      COMMAND ${CMAKE_COMMAND} -E copy_directory ${CLANG_INTRINSIC_HEADERS_DIR}
              ${CMAKE_CURRENT_BINARY_DIR}/include)

    add_enclave_dependencies(oesymcryptengine clang_intrinsic_headers_copy)

    set(CLANG_INTRINSIC_HEADERS_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
  endif ()

  enclave_compile_options(oesymcryptengine PRIVATE
                          -I${CLANG_INTRINSIC_HEADERS_DIR})
else ()
  message(
    FATAL_ERROR
      "Cannot find clang intrinstics header (required by SymCrypt OpenSSL engine)"
  )
endif ()

enclave_compile_options(
  oesymcryptengine
  PRIVATE
  # SymCrypt OpenSSL engine flags
  -maes
  -mpclmul
  -mrdrnd
  -mrdseed
  -mssse3
  -mxsave
  # Supress warnings from SymCrypt OpenSSL engine
  -Wno-shorten-64-to-32
  -Wno-sign-conversion
  -Wno-implicit-int-conversion
  -Wno-unknown-pragmas
  -Wno-unused-parameter
  # Supress warnings from clang intrinsitcs
  -Wno-bitwise-op-parentheses
  -Wno-implicit-int-float-conversion
  -Wno-shift-op-parentheses)

add_enclave_dependencies(oesymcryptengine openssl_generated)

enclave_link_libraries(oesymcryptengine PUBLIC oelibc oe_includes)

install_enclaves(
  TARGETS
  oesymcryptengine
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)