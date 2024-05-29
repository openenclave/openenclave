# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

check_submodule_not_empty(SymCrypt-OpenSSL)

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)
set(SYMCRYPT_ENGINE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/SymCrypt-OpenSSL/SymCryptEngine)

# Use CACHE so that the variables can be globally accessible
set(SYMCRYPT_VERSION_MAJOR
    "103"
    CACHE INTERNAL "")
set(SYMCRYPT_VERSION_MINOR
    "4"
    CACHE INTERNAL "")
set(SYMCRYPT_VERSION_PATCH
    "2"
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
# The SymCrypt OpenSSL engine build requires the SymCrypt header
include(FetchContent)
FetchContent_Declare(
  symcrypt_package
  SOURCE_DIR
  ${CMAKE_CURRENT_BINARY_DIR}/SymCrypt
  URL https://github.com/microsoft/SymCrypt/releases/download/v103.4.2/symcrypt-linux-oe_full-amd64-release-103.4.2-171f697.tar.gz
  URL_HASH
    SHA256=AA562EC53CFBA400A2A27027F480BC81DD9C530A5DCA32CC5C6834ED191D03FD)

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
  ${SYMCRYPT_ENGINE_DIR}/src/scossl_hmac.c
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
      clang_intrinsic_headers_copy_engine
      COMMAND ${CMAKE_COMMAND} -E copy_directory ${CLANG_INTRINSIC_HEADERS_DIR}
              ${CMAKE_CURRENT_BINARY_DIR}/include)

    add_enclave_dependencies(oesymcryptengine
                             clang_intrinsic_headers_copy_engine)

    set(CLANG_INTRINSIC_HEADERS_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
  endif ()

  enclave_compile_options(oesymcryptengine PRIVATE
                          -I${CLANG_INTRINSIC_HEADERS_DIR})
else ()
  message(
    FATAL_ERROR
      "Cannot find clang intrinstics header (required by SymCrypt OpenSSL engine) in ${CLANG_INTRINSIC_HEADERS_SEARCH_PATH}"
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
