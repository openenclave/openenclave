# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT fileencryptor_t.h fileencryptor_t.c fileencryptor_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/fileencryptor.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/fileencryptor.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx ${EDL_USE_HOST_ENTROPY})

set(CRYPTO_SRC ${OE_CRYPTO_LIB}_src)
if (OE_CRYPTO_LIB STREQUAL "openssl_3" OR OE_CRYPTO_LIB STREQUAL "openssl_symcrypt_fips")
  set(CRYPTO_SRC openssl_src)
endif ()

add_executable(
  enclave common/ecalls.cpp ${CRYPTO_SRC}/encryptor.cpp ${CRYPTO_SRC}/keys.cpp
          ${CMAKE_CURRENT_BINARY_DIR}/fileencryptor_t.c)
if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})

if (${OE_CRYPTO_LIB} STREQUAL "openssl_symcrypt_fips")
  add_custom_command(
    TARGET enclave
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/libsymcrypt.so.103
            ${CMAKE_CURRENT_BINARY_DIR}/libsymcrypt.so.103)

  target_link_libraries(
    enclave
    openenclave::oeenclave
    openenclave::oesymcryptengine
    openenclave::oecryptoopenssl
    # Workaround: refer to the root of the build location so that we don't rely on the
    # order of copy
    ${CMAKE_BINARY_DIR}/libsymcrypt.so.103
    openenclave::oelibcxx)
else()
  target_link_libraries(
    enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
    openenclave::oelibcxx)
endif()
